using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace DataProtectorWebBridge.Services
{
    /// <summary>
    /// YARA scan engine. Wraps libyara via P/Invoke. Rules are loaded from a
    /// runtime-updatable directory (synced from the central server). If
    /// libyara.dll is not deployed beside the agent, the engine reports itself
    /// unavailable and the pipeline continues with its other engines, so the
    /// build and service always run regardless of the native dependency.
    ///
    /// libyara.dll is a deployment artifact, not a build dependency: all native
    /// calls are late-bound through LoadLibrary/GetProcAddress so the managed
    /// assembly never hard-links the import.
    /// </summary>
    internal sealed class YaraScanEngine : IScanEngine
    {
        // Standard external variables real-world rule sets reference. Defined on
        // every compiler so the rules compile, and set per scan so they
        // evaluate against the actual file.
        private static readonly string[] StringExternals =
        {
            "filename", "filepath", "extension", "filetype", "owner"
        };

        private readonly string[] ruleDirectories;
        private readonly object syncRoot = new object();
        private YaraNative native;
        private readonly List<IntPtr> compiledRuleSets = new List<IntPtr>();
        private DateTime rulesStamp = DateTime.MinValue;
        private int compiledFileCount;
        private bool initialized;
        private bool available;

        public YaraScanEngine(params string[] ruleDirectories)
        {
            List<string> dirs = new List<string>();
            if (ruleDirectories != null)
            {
                foreach (string dir in ruleDirectories)
                {
                    if (!string.IsNullOrWhiteSpace(dir))
                    {
                        dirs.Add(dir);
                    }
                }
            }

            this.ruleDirectories = dirs.ToArray();

            // Ensure the primary (first) directory exists so rules can be synced
            // into it at runtime.
            if (this.ruleDirectories.Length > 0)
            {
                try
                {
                    Directory.CreateDirectory(this.ruleDirectories[0]);
                }
                catch
                {
                }
            }
        }

        public string Name { get { return "yara"; } }

        public int CompiledFileCount { get { return compiledFileCount; } }

        /// <summary>
        /// Compile the rule set ahead of the first scan so the (potentially
        /// multi-second) compile does not block a scan request and so the memory
        /// footprint settles before the agent starts its steady-state work.
        /// Safe to call repeatedly; no-op when libyara is unavailable.
        /// </summary>
        public void Warmup()
        {
            EnsureInitialized();
            if (!available || native == null)
            {
                return;
            }

            lock (syncRoot)
            {
                RefreshRulesLocked();
            }
        }

        public bool IsAvailable
        {
            get
            {
                EnsureInitialized();
                return available;
            }
        }

        private void EnsureInitialized()
        {
            if (initialized)
            {
                return;
            }

            lock (syncRoot)
            {
                if (initialized)
                {
                    return;
                }

                initialized = true;
                try
                {
                    native = YaraNative.TryLoad();
                    if (native == null)
                    {
                        available = false;
                        return;
                    }

                    int initResult = native.YrInitialize();
                    if (initResult != 0)
                    {
                        available = false;
                        return;
                    }

                    available = true;
                }
                catch
                {
                    available = false;
                }
            }
        }

        public ScanEngineResult Scan(ScanContext context)
        {
            EnsureInitialized();
            if (!available || native == null || context == null || context.Content == null || context.Content.Length == 0)
            {
                return null;
            }

            lock (syncRoot)
            {
                if (!RefreshRulesLocked())
                {
                    return null;
                }

                if (compiledRuleSets.Count == 0)
                {
                    return null;
                }

                YaraMatchState state = new YaraMatchState();
                YaraNative.YaraCallback callback = (context2, message, messageData, userData) =>
                {
                    // CALLBACK_MSG_RULE_MATCHING == 1
                    if (message == 1)
                    {
                        state.MatchCount++;
                        try
                        {
                            // The first field of YR_RULE is the identifier pointer in
                            // the ABI we target; guard against nulls.
                            IntPtr identifierPtr = Marshal.ReadIntPtr(messageData);
                            string identifier = identifierPtr != IntPtr.Zero
                                ? Marshal.PtrToStringAnsi(identifierPtr)
                                : null;
                            if (!string.IsNullOrEmpty(identifier))
                            {
                                if (state.FirstRule == null)
                                {
                                    state.FirstRule = identifier;
                                }
                                // Collect a bounded list of matched rule names so
                                // the console can show exactly which rules fired.
                                if (state.MatchedRules.Count < 64 &&
                                    !state.MatchedRules.Contains(identifier))
                                {
                                    state.MatchedRules.Add(identifier);
                                }
                            }
                        }
                        catch
                        {
                        }
                    }

                    // CALLBACK_CONTINUE == 0 (keep scanning so every matching rule
                    // is reported, not just the first).
                    return 0;
                };

                string fileName = SafeFileName(context.Path);
                string extension = SafeExtension(context.Path);

                GCHandle pinned = GCHandle.Alloc(context.Content, GCHandleType.Pinned);
                try
                {
                    foreach (IntPtr rules in compiledRuleSets)
                    {
                        // Bind external variables to this file before each scan.
                        native.DefineRulesString(rules, "filename", fileName);
                        native.DefineRulesString(rules, "filepath", context.Path ?? string.Empty);
                        native.DefineRulesString(rules, "extension", extension);
                        native.DefineRulesString(rules, "filetype", string.Empty);
                        native.DefineRulesString(rules, "owner", string.Empty);

                        native.YrRulesScanMem(
                            rules,
                            pinned.AddrOfPinnedObject(),
                            (UIntPtr)context.Content.Length,
                            0,
                            callback,
                            IntPtr.Zero,
                            10);
                    }
                }
                finally
                {
                    pinned.Free();
                    GC.KeepAlive(callback);
                }

                if (state.MatchCount == 0)
                {
                    return null;
                }

                // A YARA rule match is high-confidence. Score scales mildly with
                // the number of matching rules but a single match already lands
                // in the malicious band.
                int score = 80 + Math.Min(20, (state.MatchCount - 1) * 5);

                // Build a reason that names the matched rules (capped) so the
                // console shows which rules fired, not just a count.
                string ruleList = string.Join(", ", state.MatchedRules);
                string reason;
                if (state.MatchedRules.Count == 0)
                {
                    reason = "matched " + state.MatchCount + " rule(s)";
                }
                else if (state.MatchCount > state.MatchedRules.Count)
                {
                    reason = "matched " + state.MatchCount + " rule(s): " + ruleList +
                             " (+" + (state.MatchCount - state.MatchedRules.Count) + " more)";
                }
                else
                {
                    reason = "matched " + state.MatchCount + " rule(s): " + ruleList;
                }

                return new ScanEngineResult
                {
                    Score = score,
                    ReasonFlags = ScanReasonFlags.YaraMatch,
                    Reason = reason,
                    MatchedRules = state.MatchedRules.ToArray()
                };
            }
        }

        private static string SafeFileName(string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                return string.Empty;
            }

            try
            {
                return Path.GetFileName(path);
            }
            catch
            {
                return string.Empty;
            }
        }

        private static string SafeExtension(string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                return string.Empty;
            }

            try
            {
                string ext = Path.GetExtension(path);
                return ext ?? string.Empty;
            }
            catch
            {
                return string.Empty;
            }
        }

        private void DestroyRuleSetsLocked()
        {
            foreach (IntPtr rules in compiledRuleSets)
            {
                if (rules != IntPtr.Zero)
                {
                    native.YrRulesDestroy(rules);
                }
            }
            compiledRuleSets.Clear();
            compiledFileCount = 0;
        }

        // Caller holds syncRoot. Compiles every clean rule file into a SINGLE
        // shared YR_RULES object (libyara is built to hold thousands of rules in
        // one object). A throwaway test-compiler validates each file first so a
        // malformed file is skipped without poisoning the shared compiler. Each
        // file is added under a unique namespace to avoid duplicate-identifier
        // collisions across rule sets. This keeps memory bounded (one arena
        // instead of thousands) and scanning fast (one pass instead of N).
        private bool RefreshRulesLocked()
        {
            try
            {
                List<string> ruleFileList = new List<string>();
                foreach (string dir in ruleDirectories)
                {
                    if (Directory.Exists(dir))
                    {
                        ruleFileList.AddRange(Directory.GetFiles(dir, "*.yar*", SearchOption.AllDirectories));
                    }
                }
                string[] ruleFiles = ruleFileList.ToArray();

                if (ruleFiles.Length == 0)
                {
                    DestroyRuleSetsLocked();
                    return false;
                }

                DateTime newest = DateTime.MinValue;
                foreach (string file in ruleFiles)
                {
                    DateTime stamp = File.GetLastWriteTimeUtc(file);
                    if (stamp > newest)
                    {
                        newest = stamp;
                    }
                }

                if (compiledRuleSets.Count > 0 && newest == rulesStamp)
                {
                    return true;
                }

                IntPtr sharedCompiler;
                if (native.YrCompilerCreate(out sharedCompiler) != 0 || sharedCompiler == IntPtr.Zero)
                {
                    return compiledRuleSets.Count > 0;
                }

                int compiledFiles = 0;
                int skippedFiles = 0;

                try
                {
                    DefineCompilerExternals(sharedCompiler);

                    int namespaceIndex = 0;
                    foreach (string file in ruleFiles)
                    {
                        string ruleText;
                        try
                        {
                            ruleText = File.ReadAllText(file);
                        }
                        catch
                        {
                            skippedFiles++;
                            continue;
                        }

                        // Validate the file in isolation first. yr_compiler_add_string
                        // returns the number of errors; a poisoned compiler cannot
                        // produce rules, so we never add a bad file to the shared one.
                        if (!FileCompilesCleanly(ruleText))
                        {
                            skippedFiles++;
                            continue;
                        }

                        string ns = "dp_ns_" + namespaceIndex.ToString(System.Globalization.CultureInfo.InvariantCulture);
                        int errors = native.YrCompilerAddString(sharedCompiler, ruleText, ns);
                        if (errors != 0)
                        {
                            // Should not happen after the clean pre-test, but guard.
                            skippedFiles++;
                            continue;
                        }

                        namespaceIndex++;
                        compiledFiles++;
                    }

                    if (compiledFiles == 0)
                    {
                        return compiledRuleSets.Count > 0;
                    }

                    IntPtr rules;
                    if (native.YrCompilerGetRules(sharedCompiler, out rules) != 0 || rules == IntPtr.Zero)
                    {
                        return compiledRuleSets.Count > 0;
                    }

                    DestroyRuleSetsLocked();
                    compiledRuleSets.Add(rules);
                    compiledFileCount = compiledFiles;
                    rulesStamp = newest;

                    Console.WriteLine(DateTime.Now.ToString("s") + " YARA compiled " + compiledFiles +
                        " rule file(s) into 1 rule set (" + skippedFiles + " skipped, " +
                        ruleFiles.Length + " total).");
                    return true;
                }
                finally
                {
                    native.YrCompilerDestroy(sharedCompiler);
                }
            }
            catch
            {
                return compiledRuleSets.Count > 0;
            }
        }

        private void DefineCompilerExternals(IntPtr compiler)
        {
            foreach (string ext in StringExternals)
            {
                native.DefineCompilerString(compiler, ext, string.Empty);
            }
        }

        // Compile a single rule file in a disposable compiler to decide whether
        // it is safe to add to the shared compiler.
        private bool FileCompilesCleanly(string ruleText)
        {
            IntPtr testCompiler;
            if (native.YrCompilerCreate(out testCompiler) != 0 || testCompiler == IntPtr.Zero)
            {
                return false;
            }

            try
            {
                DefineCompilerExternals(testCompiler);
                int errors = native.YrCompilerAddString(testCompiler, ruleText, null);
                return errors == 0;
            }
            catch
            {
                return false;
            }
            finally
            {
                native.YrCompilerDestroy(testCompiler);
            }
        }

        private sealed class YaraMatchState
        {
            public int MatchCount;
            public string FirstRule;
            public readonly List<string> MatchedRules = new List<string>();
        }
    }

    /// <summary>
    /// Late-bound binding to libyara.dll. All entry points are resolved at
    /// runtime so the managed assembly does not require the native library at
    /// build time. Returns null from TryLoad when libyara is not present.
    /// </summary>
    internal sealed class YaraNative
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr LoadLibrary(string name);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr module, string name);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int YaraInitDelegate();

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int YaraCompilerCreateDelegate(out IntPtr compiler);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int YaraCompilerAddStringDelegate(IntPtr compiler, string ruleString, string ns);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int YaraCompilerDefineStringDelegate(IntPtr compiler, string identifier, string value);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int YaraCompilerDefineIntegerDelegate(IntPtr compiler, string identifier, long value);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int YaraCompilerDefineBooleanDelegate(IntPtr compiler, string identifier, int value);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int YaraRulesDefineStringDelegate(IntPtr rules, string identifier, string value);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int YaraRulesDefineIntegerDelegate(IntPtr rules, string identifier, long value);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int YaraRulesDefineBooleanDelegate(IntPtr rules, string identifier, int value);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int YaraCompilerGetRulesDelegate(IntPtr compiler, out IntPtr rules);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void YaraCompilerDestroyDelegate(IntPtr compiler);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void YaraRulesDestroyDelegate(IntPtr rules);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int YaraCallback(IntPtr context, int message, IntPtr messageData, IntPtr userData);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int YaraRulesScanMemDelegate(
            IntPtr rules,
            IntPtr buffer,
            UIntPtr bufferLength,
            int flags,
            YaraCallback callback,
            IntPtr userData,
            int timeout);

        private YaraInitDelegate initFn;
        private YaraCompilerCreateDelegate compilerCreateFn;
        private YaraCompilerAddStringDelegate compilerAddStringFn;
        private YaraCompilerGetRulesDelegate compilerGetRulesFn;
        private YaraCompilerDestroyDelegate compilerDestroyFn;
        private YaraRulesDestroyDelegate rulesDestroyFn;
        private YaraRulesScanMemDelegate rulesScanMemFn;
        private YaraCompilerDefineStringDelegate compilerDefineStringFn;
        private YaraCompilerDefineIntegerDelegate compilerDefineIntegerFn;
        private YaraCompilerDefineBooleanDelegate compilerDefineBooleanFn;
        private YaraRulesDefineStringDelegate rulesDefineStringFn;
        private YaraRulesDefineIntegerDelegate rulesDefineIntegerFn;
        private YaraRulesDefineBooleanDelegate rulesDefineBooleanFn;

        public static YaraNative TryLoad()
        {
            // Probe common deployment names next to the agent / on PATH.
            string[] candidates = { "libyara.dll", "yara.dll", "libyara64.dll" };
            IntPtr module = IntPtr.Zero;
            foreach (string candidate in candidates)
            {
                module = LoadLibrary(candidate);
                if (module != IntPtr.Zero)
                {
                    break;
                }
            }

            if (module == IntPtr.Zero)
            {
                return null;
            }

            try
            {
                YaraNative native = new YaraNative();
                native.initFn = GetDelegate<YaraInitDelegate>(module, "yr_initialize");
                native.compilerCreateFn = GetDelegate<YaraCompilerCreateDelegate>(module, "yr_compiler_create");
                native.compilerAddStringFn = GetDelegate<YaraCompilerAddStringDelegate>(module, "yr_compiler_add_string");
                native.compilerGetRulesFn = GetDelegate<YaraCompilerGetRulesDelegate>(module, "yr_compiler_get_rules");
                native.compilerDestroyFn = GetDelegate<YaraCompilerDestroyDelegate>(module, "yr_compiler_destroy");
                native.rulesDestroyFn = GetDelegate<YaraRulesDestroyDelegate>(module, "yr_rules_destroy");
                native.rulesScanMemFn = GetDelegate<YaraRulesScanMemDelegate>(module, "yr_rules_scan_mem");

                if (native.initFn == null ||
                    native.compilerCreateFn == null ||
                    native.compilerAddStringFn == null ||
                    native.compilerGetRulesFn == null ||
                    native.compilerDestroyFn == null ||
                    native.rulesDestroyFn == null ||
                    native.rulesScanMemFn == null)
                {
                    return null;
                }

                // External-variable definition entry points are optional: when
                // present they let real-world rules that reference filename /
                // filepath / extension / filetype / owner compile and evaluate.
                native.compilerDefineStringFn = GetDelegate<YaraCompilerDefineStringDelegate>(module, "yr_compiler_define_string_variable");
                native.compilerDefineIntegerFn = GetDelegate<YaraCompilerDefineIntegerDelegate>(module, "yr_compiler_define_integer_variable");
                native.compilerDefineBooleanFn = GetDelegate<YaraCompilerDefineBooleanDelegate>(module, "yr_compiler_define_boolean_variable");
                native.rulesDefineStringFn = GetDelegate<YaraRulesDefineStringDelegate>(module, "yr_rules_define_string_variable");
                native.rulesDefineIntegerFn = GetDelegate<YaraRulesDefineIntegerDelegate>(module, "yr_rules_define_integer_variable");
                native.rulesDefineBooleanFn = GetDelegate<YaraRulesDefineBooleanDelegate>(module, "yr_rules_define_boolean_variable");

                return native;
            }
            catch
            {
                return null;
            }
        }

        private static T GetDelegate<T>(IntPtr module, string name) where T : class
        {
            IntPtr proc = GetProcAddress(module, name);
            if (proc == IntPtr.Zero)
            {
                return null;
            }

            return Marshal.GetDelegateForFunctionPointer(proc, typeof(T)) as T;
        }

        public int YrInitialize() { return initFn(); }
        public int YrCompilerCreate(out IntPtr compiler) { return compilerCreateFn(out compiler); }
        public int YrCompilerAddString(IntPtr compiler, string ruleString, string ns) { return compilerAddStringFn(compiler, ruleString, ns); }
        public int YrCompilerGetRules(IntPtr compiler, out IntPtr rules) { return compilerGetRulesFn(compiler, out rules); }
        public void YrCompilerDestroy(IntPtr compiler) { compilerDestroyFn(compiler); }
        public void YrRulesDestroy(IntPtr rules) { rulesDestroyFn(rules); }

        public void DefineCompilerString(IntPtr compiler, string identifier, string value)
        {
            if (compilerDefineStringFn != null) { compilerDefineStringFn(compiler, identifier, value); }
        }

        public void DefineCompilerInteger(IntPtr compiler, string identifier, long value)
        {
            if (compilerDefineIntegerFn != null) { compilerDefineIntegerFn(compiler, identifier, value); }
        }

        public void DefineCompilerBoolean(IntPtr compiler, string identifier, bool value)
        {
            if (compilerDefineBooleanFn != null) { compilerDefineBooleanFn(compiler, identifier, value ? 1 : 0); }
        }

        public void DefineRulesString(IntPtr rules, string identifier, string value)
        {
            if (rulesDefineStringFn != null) { rulesDefineStringFn(rules, identifier, value); }
        }

        public void DefineRulesInteger(IntPtr rules, string identifier, long value)
        {
            if (rulesDefineIntegerFn != null) { rulesDefineIntegerFn(rules, identifier, value); }
        }

        public void DefineRulesBoolean(IntPtr rules, string identifier, bool value)
        {
            if (rulesDefineBooleanFn != null) { rulesDefineBooleanFn(rules, identifier, value ? 1 : 0); }
        }

        public int YrRulesScanMem(IntPtr rules, IntPtr buffer, UIntPtr bufferLength, int flags, YaraCallback callback, IntPtr userData, int timeout)
        {
            return rulesScanMemFn(rules, buffer, bufferLength, flags, callback, userData, timeout);
        }
    }

    /// <summary>
    /// Heuristic PE / script analysis engine. This ports the structure /
    /// entropy / suspicious-string logic that previously lived (incorrectly) in
    /// the kernel. Running it in user mode means it can be tuned and extended
    /// freely without touching the signed driver.
    /// </summary>
    internal sealed class HeuristicPeScanEngine : IScanEngine
    {
        private const int EntropyHigh = 700;   // 7.00 bits/byte, scaled x100
        private const int EntropyPacked = 740;  // 7.40 bits/byte

        public string Name { get { return "heuristic"; } }

        public bool IsAvailable { get { return true; } }

        public ScanEngineResult Scan(ScanContext context)
        {
            if (context == null || context.Content == null || context.Content.Length == 0)
            {
                return null;
            }

            byte[] data = context.Content;
            bool isPe = data.Length >= 2 && data[0] == (byte)'M' && data[1] == (byte)'Z';
            int entropy = EntropyScaled(data);
            int score = 0;
            uint flags = 0;
            List<string> notes = new List<string>();

            if (isPe)
            {
                bool validPe;
                score += ScorePe(data, context.FileSize, ref flags, notes, entropy, out validPe);

                if (!validPe)
                {
                    // MZ magic but no valid PE header. A file with an executable
                    // extension that begins with 'MZ' yet has no real PE
                    // structure is almost always raw shellcode, a stomped
                    // header, or a corrupt/packed dropper - treat it as a strong
                    // signal rather than ignoring it.
                    score += 45;
                    notes.Add("MZ-without-PE");

                    // Small MZ stubs (a few KB) with no PE header are the classic
                    // "MZ + shellcode" stager shape.
                    if (context.FileSize != 0 && context.FileSize < 64 * 1024)
                    {
                        score += 15;
                        flags |= ScanReasonFlags.TinyImage;
                        notes.Add("tiny-mz-stub");
                    }

                    if (entropy >= EntropyHigh)
                    {
                        score += 10;
                        flags |= ScanReasonFlags.HighEntropy;
                        notes.Add("high-entropy");
                    }

                    score += ScoreSuspiciousStrings(data, ref flags, notes);
                }
            }
            else
            {
                // Script / non-PE dropper.
                flags |= ScanReasonFlags.ScriptDropper;
                int stringScore = ScoreSuspiciousStrings(data, ref flags, notes);
                score += stringScore;
                if (entropy >= 550)
                {
                    score += 14;
                    flags |= ScanReasonFlags.HighEntropy;
                    notes.Add("dense/obfuscated");
                }
            }

            if (score <= 0)
            {
                return null;
            }

            // Heuristics normally cap below the YARA/hash engines so they rarely
            // block on their own. The "MZ-without-PE" shellcode-stub shape is an
            // exception: it is high-confidence on its own, so allow it into the
            // malicious band.
            bool strongMalformedPe = notes.Contains("MZ-without-PE");
            int cap = strongMalformedPe ? 85 : 60;
            if (score > cap)
            {
                score = cap;
            }

            return new ScanEngineResult
            {
                Score = score,
                ReasonFlags = flags,
                Reason = notes.Count == 0 ? "heuristic" : string.Join(",", notes)
            };
        }

        private int ScorePe(byte[] data, ulong fileSize, ref uint flags, List<string> notes, int entropy, out bool validPe)
        {
            int score = 0;
            validPe = false;

            if (data.Length < 0x40)
            {
                return score;
            }

            int peOffset = BitConverter.ToInt32(data, 0x3C);
            if (peOffset <= 0 || peOffset + 24 > data.Length)
            {
                return score;
            }

            if (!(data[peOffset] == (byte)'P' && data[peOffset + 1] == (byte)'E' &&
                  data[peOffset + 2] == 0 && data[peOffset + 3] == 0))
            {
                return score;
            }

            // Confirmed PE structure.
            validPe = true;
            flags |= ScanReasonFlags.ValidPe;

            ushort numberOfSections = BitConverter.ToUInt16(data, peOffset + 6);
            ushort sizeOfOptionalHeader = BitConverter.ToUInt16(data, peOffset + 20);
            ushort optionalMagic = 0;
            if (peOffset + 24 + 2 <= data.Length)
            {
                optionalMagic = BitConverter.ToUInt16(data, peOffset + 24);
            }

            uint importRva = 0;
            int importEntryOffset = 0;
            if (optionalMagic == 0x10B)
            {
                importEntryOffset = peOffset + 24 + 0x60 + 8;
            }
            else if (optionalMagic == 0x20B)
            {
                importEntryOffset = peOffset + 24 + 0x70 + 8;
            }

            if (importEntryOffset != 0 && importEntryOffset + 8 <= data.Length)
            {
                importRva = BitConverter.ToUInt32(data, importEntryOffset);
            }

            if (importRva == 0)
            {
                score += 12;
                flags |= ScanReasonFlags.NoImports;
                notes.Add("no-imports");
            }

            int sectionTableOffset = peOffset + 24 + sizeOfOptionalHeader;
            bool sawWx = false;
            bool sawPacker = false;
            for (int i = 0; i < numberOfSections; i++)
            {
                int sectionOffset = sectionTableOffset + i * 40;
                if (sectionOffset + 40 > data.Length)
                {
                    break;
                }

                StringBuilder nameBuilder = new StringBuilder(8);
                for (int c = 0; c < 8; c++)
                {
                    byte ch = data[sectionOffset + c];
                    if (ch >= 0x20 && ch < 0x7F)
                    {
                        nameBuilder.Append((char)ch);
                    }
                }
                string sectionName = nameBuilder.ToString().ToLowerInvariant();
                uint characteristics = BitConverter.ToUInt32(data, sectionOffset + 36);

                if ((characteristics & 0x20000000u) != 0 && (characteristics & 0x80000000u) != 0)
                {
                    sawWx = true;
                }

                if (sectionName.Contains("upx") || sectionName.Contains("aspack") ||
                    sectionName.Contains("themida") || sectionName.Contains("petite") ||
                    sectionName.Contains("mpress"))
                {
                    sawPacker = true;
                }
            }

            if (sawWx)
            {
                score += 16;
                flags |= ScanReasonFlags.WxSection;
                notes.Add("WX-section");
            }

            if (sawPacker)
            {
                score += 20;
                flags |= ScanReasonFlags.PackerSection;
                notes.Add("packer-section");
            }

            if (entropy >= EntropyPacked)
            {
                score += 26;
                flags |= ScanReasonFlags.HighEntropy;
                notes.Add("packed-entropy");
            }
            else if (entropy >= EntropyHigh)
            {
                score += 14;
                flags |= ScanReasonFlags.HighEntropy;
                notes.Add("high-entropy");
            }

            if (fileSize != 0 && fileSize < 4096)
            {
                score += 6;
                flags |= ScanReasonFlags.TinyImage;
                notes.Add("tiny-image");
            }

            score += ScoreSuspiciousStrings(data, ref flags, notes);
            return score;
        }

        private static int ScoreSuspiciousStrings(byte[] data, ref uint flags, List<string> notes)
        {
            string[] tokens =
            {
                "virtualallocex", "writeprocessmemory", "createremotethread",
                "ntunmapviewofsection", "queueuserapc", "urldownloadtofile",
                "frombase64string", "invoke-expression", "downloadstring",
                "reflection.assembly", "shellexecute", "winexec"
            };

            string haystack = AsciiLower(data);
            int score = 0;
            int matches = 0;
            foreach (string token in tokens)
            {
                if (haystack.IndexOf(token, StringComparison.Ordinal) >= 0)
                {
                    score += 8;
                    matches++;
                }
            }

            if (matches > 0)
            {
                flags |= ScanReasonFlags.SuspiciousImport | ScanReasonFlags.SuspiciousString;
                notes.Add("suspicious-api(" + matches + ")");
            }

            return Math.Min(score, 40);
        }

        private static string AsciiLower(byte[] data)
        {
            int limit = Math.Min(data.Length, 64 * 1024);
            StringBuilder builder = new StringBuilder(limit);
            for (int i = 0; i < limit; i++)
            {
                byte b = data[i];
                if (b >= (byte)'A' && b <= (byte)'Z')
                {
                    builder.Append((char)(b - 'A' + 'a'));
                }
                else if (b >= 0x20 && b < 0x7F)
                {
                    builder.Append((char)b);
                }
                else
                {
                    builder.Append(' ');
                }
            }

            return builder.ToString();
        }

        private static int EntropyScaled(byte[] data)
        {
            int limit = Math.Min(data.Length, 256 * 1024);
            if (limit == 0)
            {
                return 0;
            }

            int[] histogram = new int[256];
            for (int i = 0; i < limit; i++)
            {
                histogram[data[i]]++;
            }

            double entropy = 0.0;
            for (int i = 0; i < 256; i++)
            {
                if (histogram[i] == 0)
                {
                    continue;
                }

                double p = (double)histogram[i] / limit;
                entropy -= p * Math.Log(p, 2);
            }

            int scaled = (int)(entropy * 100.0);
            if (scaled > 800)
            {
                scaled = 800;
            }

            return scaled;
        }
    }
}
