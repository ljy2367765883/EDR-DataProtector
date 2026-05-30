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
        private readonly string ruleDirectory;
        private readonly object syncRoot = new object();
        private YaraNative native;
        private IntPtr compiledRules = IntPtr.Zero;
        private DateTime rulesStamp = DateTime.MinValue;
        private bool initialized;
        private bool available;

        public YaraScanEngine(string ruleDirectory)
        {
            this.ruleDirectory = ruleDirectory;
            try
            {
                Directory.CreateDirectory(ruleDirectory);
            }
            catch
            {
            }
        }

        public string Name { get { return "yara"; } }

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

                if (compiledRules == IntPtr.Zero)
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
                            if (!string.IsNullOrEmpty(identifier) && state.FirstRule == null)
                            {
                                state.FirstRule = identifier;
                            }
                        }
                        catch
                        {
                        }
                    }

                    // CALLBACK_CONTINUE == 0
                    return 0;
                };

                GCHandle pinned = GCHandle.Alloc(context.Content, GCHandleType.Pinned);
                try
                {
                    int scanResult = native.YrRulesScanMem(
                        compiledRules,
                        pinned.AddrOfPinnedObject(),
                        (UIntPtr)context.Content.Length,
                        0,
                        callback,
                        IntPtr.Zero,
                        0);

                    if (scanResult != 0 || state.MatchCount == 0)
                    {
                        return null;
                    }
                }
                finally
                {
                    pinned.Free();
                    GC.KeepAlive(callback);
                }

                // A YARA rule match is high-confidence. Score scales mildly with
                // the number of matching rules but a single match already lands
                // in the malicious band.
                int score = 80 + Math.Min(20, (state.MatchCount - 1) * 5);
                string reason = state.FirstRule == null
                    ? ("matched " + state.MatchCount + " rule(s)")
                    : ("matched rule '" + state.FirstRule + "'" + (state.MatchCount > 1 ? (" +" + (state.MatchCount - 1)) : string.Empty));

                return new ScanEngineResult
                {
                    Score = score,
                    ReasonFlags = ScanReasonFlags.YaraMatch,
                    Reason = reason
                };
            }
        }

        // Caller holds syncRoot.
        private bool RefreshRulesLocked()
        {
            try
            {
                string[] ruleFiles = Directory.Exists(ruleDirectory)
                    ? Directory.GetFiles(ruleDirectory, "*.yar*", SearchOption.AllDirectories)
                    : new string[0];

                if (ruleFiles.Length == 0)
                {
                    // No rules deployed: nothing to do, but engine stays "available"
                    // so it picks up rules as soon as the central server syncs them.
                    if (compiledRules != IntPtr.Zero)
                    {
                        native.YrRulesDestroy(compiledRules);
                        compiledRules = IntPtr.Zero;
                    }
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

                if (compiledRules != IntPtr.Zero && newest == rulesStamp)
                {
                    return true;
                }

                IntPtr compiler;
                if (native.YrCompilerCreate(out compiler) != 0 || compiler == IntPtr.Zero)
                {
                    return false;
                }

                try
                {
                    foreach (string file in ruleFiles)
                    {
                        string ruleText;
                        try
                        {
                            ruleText = File.ReadAllText(file);
                        }
                        catch
                        {
                            continue;
                        }

                        // YrCompilerAddString returns the number of errors.
                        native.YrCompilerAddString(compiler, ruleText, null);
                    }

                    IntPtr newRules;
                    if (native.YrCompilerGetRules(compiler, out newRules) != 0 || newRules == IntPtr.Zero)
                    {
                        return compiledRules != IntPtr.Zero;
                    }

                    if (compiledRules != IntPtr.Zero)
                    {
                        native.YrRulesDestroy(compiledRules);
                    }

                    compiledRules = newRules;
                    rulesStamp = newest;
                    return true;
                }
                finally
                {
                    native.YrCompilerDestroy(compiler);
                }
            }
            catch
            {
                return compiledRules != IntPtr.Zero;
            }
        }

        private sealed class YaraMatchState
        {
            public int MatchCount;
            public string FirstRule;
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
                score += ScorePe(data, context.FileSize, ref flags, notes, entropy);
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

            if (score > 60)
            {
                score = 60; // heuristic caps below YARA/hash so it rarely blocks alone
            }

            return new ScanEngineResult
            {
                Score = score,
                ReasonFlags = flags,
                Reason = notes.Count == 0 ? "heuristic" : string.Join(",", notes)
            };
        }

        private int ScorePe(byte[] data, ulong fileSize, ref uint flags, List<string> notes, int entropy)
        {
            int score = 0;
            flags |= ScanReasonFlags.ValidPe;

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
