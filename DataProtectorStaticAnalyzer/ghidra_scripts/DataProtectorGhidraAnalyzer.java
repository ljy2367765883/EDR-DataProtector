/* ###
 * IP: DATAPROTECTOR-GHIDRA-ADAPTER
 *
 * Portions of this script are adapted from Ghidra headless/decompiler script
 * examples such as ShowCCallsScript.java and PrintFunctionCallTreesScript.java.
 * Ghidra is licensed under the Apache License, Version 2.0.
 *
 * DataProtector changes:
 * - Converts the interactive script pattern into a deterministic headless export.
 * - Emits bounded JSON for AI static triage, custom rule scoring, and call graph rendering.
 * - Adds Windows malware-oriented import/string/function feature extraction.
 * ##
 */
//@category DataProtector

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.util.DefinedStringIterator;
import ghidra.util.task.TaskMonitor;

public class DataProtectorGhidraAnalyzer extends GhidraScript {
	private static final int DEFAULT_MAX_FUNCTIONS = 220;
	private static final int DEFAULT_MAX_DECOMPILER_CHARS = 160000;
	private static final int MAX_IMPORTS = 1200;
	private static final int MAX_STRINGS = 500;
	private static final int MAX_EDGES = 1500;
	private static final int MAX_FEATURES = 800;
	private static final int MAX_INSTRUCTIONS_PER_FUNCTION = 96;

	private static final String[] DANGEROUS_IMPORTS = {
		"virtualalloc", "virtualallocex", "virtualprotect", "virtualprotectex",
		"writeprocessmemory", "readprocessmemory", "createremotethread",
		"ntcreatethreadex", "rtlcreateuserthread", "queueuserapc", "ntqueueapcthread",
		"setwindowshookex", "loadlibrarya", "loadlibraryw", "ldrloaddll",
		"getprocaddress", "ntprotectvirtualmemory", "ntallocatevirtualmemory",
		"ntwritevirtualmemory", "ntreadvirtualmemory", "ntmapviewofsection",
		"createprocessa", "createprocessw", "createprocessasuserw",
		"winexec", "shellexecutea", "shellexecutew",
		"regsetvalueexa", "regsetvalueexw", "regcreatekeyexa", "regcreatekeyexw",
		"createthread", "openprocess", "openthread", "duplicatehandle",
		"adjusttokenprivileges", "openprocesstoken", "logonuserw",
		"createtoolhelp32snapshot", "process32firstw", "process32nextw",
		"enumprocesses", "enumprocessmodules", "mini_dump_write_dump", "minidumpwritedump",
		"cryptprotectdata", "cryptunprotectdata", "internetopen", "internetconnect",
		"httpopenrequest", "httpsendrequest", "winhttpopen", "winhttpconnect",
		"winhttpsendrequest", "urldownloadtofile", "wsastartup", "connect", "send", "recv",
		"createservice", "startservice", "openservice", "controlservice",
		"createfilew", "writefile", "deletefilew", "movefileexw",
		"wow64disablewow64fsredirection", "setthreadcontext", "getthreadcontext",
		"resumeThread", "nttestalert", "zwtestalert"
	};

	private static final String[] SUSPICIOUS_STRING_MARKERS = {
		"powershell", "cmd.exe", "rundll32", "regsvr32", "mshta", "wscript", "cscript",
		"wmic", "schtasks", "sc.exe", "bitsadmin", "certutil", "vssadmin",
		"\\\\.\\pipe\\", "software\\microsoft\\windows\\currentversion\\run",
		"software\\microsoft\\windows\\currentversion\\runonce", "\\startup\\",
		"lsass", "sam", "security", "system32\\config", "mimikatz", "sekurlsa",
		"virtualalloc", "writeprocessmemory", "createremotethread", "ntcreatethreadex",
		"http://", "https://", ".onion", "user-agent", "beacon", "shellcode",
		"process hollow", "amsi", "etw", "syscall", "ntdll.dll"
	};

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		String outputPath = args.length > 0 ? args[0] : "";
		int maxFunctions = parseIntArg(args, 1, DEFAULT_MAX_FUNCTIONS, 10, 3000);
		int maxDecompilerChars = parseIntArg(args, 2, DEFAULT_MAX_DECOMPILER_CHARS, 20000, 2500000);

		Map<String, Object> report = new LinkedHashMap<>();
		report.put("schema", "dataprotector.static.ghidra.v1");
		report.put("source", "Ghidra source-derived DataProtectorGhidraAnalyzer");
		report.put("ghidraAdapter", "headless-script/decompiler/function-reference-graph");
		report.put("program", buildProgramSummary(currentProgram));
		report.put("imports", collectImports());
		report.put("strings", collectStrings());

		FunctionExportResult functionResult = collectFunctions(maxFunctions, maxDecompilerChars);
		report.put("functions", functionResult.functions);
		report.put("callGraph", functionResult.edges);
		report.put("features", buildFeatureSummary(report, functionResult));
		report.put("limits", buildLimits(maxFunctions, maxDecompilerChars, functionResult));

		String json = toJson(report);
		if (outputPath == null || outputPath.trim().isEmpty()) {
			println(json);
			return;
		}

		File output = new File(outputPath);
		File parent = output.getParentFile();
		if (parent != null) {
			parent.mkdirs();
		}

		try (PrintWriter writer = new PrintWriter(new OutputStreamWriter(new FileOutputStream(output), StandardCharsets.UTF_8))) {
			writer.write(json);
		}
		println("DataProtector static analysis report written: " + output.getAbsolutePath());
	}

	private Map<String, Object> buildProgramSummary(Program program) {
		Map<String, Object> result = new LinkedHashMap<>();
		Language language = program.getLanguage();
		result.put("name", program.getName());
		result.put("executablePath", safe(program.getExecutablePath()));
		result.put("executableFormat", safe(program.getExecutableFormat()));
		result.put("languageId", language == null ? "" : language.getLanguageID().getIdAsString());
		result.put("processor", language == null ? "" : language.getProcessor().toString());
		result.put("compilerSpec", program.getCompilerSpec() == null ? "" : program.getCompilerSpec().getCompilerSpecID().getIdAsString());
		result.put("imageBase", currentProgram.getImageBase() == null ? "" : currentProgram.getImageBase().toString());
		result.put("addressSize", language == null ? 0 : language.getDefaultSpace().getSize());
		result.put("functionCount", program.getFunctionManager().getFunctionCount());
		result.put("entryPoints", collectEntryPoints());
		return result;
	}

	private List<String> collectEntryPoints() {
		List<String> entries = new ArrayList<>();
		AddressIterator iterator = currentProgram.getSymbolTable().getExternalEntryPointIterator();
		while (iterator.hasNext() && entries.size() < 64) {
			entries.add(iterator.next().toString());
		}
		return entries;
	}

	private List<Map<String, Object>> collectImports() {
		List<Map<String, Object>> imports = new ArrayList<>();
		SymbolIterator symbols = currentProgram.getSymbolTable().getExternalSymbols();
		while (symbols.hasNext() && imports.size() < MAX_IMPORTS) {
			Symbol symbol = symbols.next();
			if (symbol == null) {
				continue;
			}
			Map<String, Object> item = new LinkedHashMap<>();
			item.put("name", safe(symbol.getName()));
			item.put("namespace", symbol.getParentNamespace() == null ? "" : safe(symbol.getParentNamespace().getName(true)));
			item.put("address", symbol.getAddress() == null ? "" : symbol.getAddress().toString());
			item.put("danger", matchAny(symbol.getName(), DANGEROUS_IMPORTS));
			imports.add(item);
		}
		Collections.sort(imports, Comparator.comparing(o -> String.valueOf(o.get("name")).toLowerCase(Locale.ROOT)));
		return imports;
	}

	private List<Map<String, Object>> collectStrings() {
		List<Map<String, Object>> strings = new ArrayList<>();
		try {
			for (Data data : DefinedStringIterator.forProgram(currentProgram)) {
				if (data == null || strings.size() >= MAX_STRINGS) {
					break;
				}
				String value = "";
				try {
					StringDataInstance instance = StringDataInstance.getStringDataInstance(data);
					value = instance == null ? "" : instance.getStringValue();
				}
				catch (Exception ignored) {
					Object raw = data.getValue();
					value = raw == null ? "" : raw.toString();
				}
				value = normalizeText(value, 600);
				if (value.length() < 4) {
					continue;
				}
				Map<String, Object> item = new LinkedHashMap<>();
				item.put("address", data.getAddress() == null ? "" : data.getAddress().toString());
				item.put("value", value);
				item.put("suspicious", matchAny(value, SUSPICIOUS_STRING_MARKERS));
				strings.add(item);
			}
		}
		catch (Exception ex) {
			Map<String, Object> item = new LinkedHashMap<>();
			item.put("address", "");
			item.put("value", "string extraction failed: " + ex.getMessage());
			item.put("suspicious", false);
			strings.add(item);
		}
		return strings;
	}

	private FunctionExportResult collectFunctions(int maxFunctions, int maxDecompilerChars) {
		FunctionExportResult result = new FunctionExportResult();
		DecompInterface decompiler = setupDecompiler(currentProgram);
		int remainingDecompilerChars = maxDecompilerChars;
		try {
			if (!decompiler.openProgram(currentProgram)) {
				result.decompilerError = safe(decompiler.getLastMessage());
				return result;
			}

			FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
			while (iterator.hasNext() && result.functions.size() < maxFunctions) {
				Function function = iterator.next();
				if (function == null || function.isExternal()) {
					continue;
				}

				Map<String, Object> item = exportFunction(function, decompiler, remainingDecompilerChars);
				String pseudo = String.valueOf(item.get("pseudocode"));
				remainingDecompilerChars = Math.max(0, remainingDecompilerChars - pseudo.length());
				result.functions.add(item);
				collectCallEdges(function, result.edges);
			}
		}
		catch (Exception ex) {
			result.decompilerError = ex.getMessage();
		}
		finally {
			decompiler.dispose();
		}
		result.decompiledChars = maxDecompilerChars - remainingDecompilerChars;
		return result;
	}

	private Map<String, Object> exportFunction(Function function, DecompInterface decompiler, int remainingDecompilerChars) {
		Map<String, Object> item = new LinkedHashMap<>();
		item.put("name", safe(function.getName()));
		item.put("entry", function.getEntryPoint() == null ? "" : function.getEntryPoint().toString());
		item.put("signature", safe(function.getPrototypeString(false, false)));
		item.put("bodySize", function.getBody() == null ? 0 : function.getBody().getNumAddresses());
		item.put("called", functionNames(function.getCalledFunctions(monitor), 80));
		item.put("calling", functionNames(function.getCallingFunctions(monitor), 80));
		item.put("instructions", collectInstructions(function));

		String pseudocode = "";
		String error = "";
		if (remainingDecompilerChars > 0) {
			try {
				DecompileResults decompileResults = decompiler.decompileFunction(function, 20, monitor);
				if (decompileResults != null && decompileResults.decompileCompleted() && decompileResults.getDecompiledFunction() != null) {
					pseudocode = normalizeText(decompileResults.getDecompiledFunction().getC(), remainingDecompilerChars);
				}
				else if (decompileResults != null) {
					error = safe(decompileResults.getErrorMessage());
				}
			}
			catch (Exception ex) {
				error = safe(ex.getMessage());
			}
		}
		item.put("pseudocode", pseudocode);
		item.put("decompilerError", error);
		item.put("featureHits", functionFeatureHits(item));
		return item;
	}

	private DecompInterface setupDecompiler(Program program) {
		DecompileOptions options = new DecompileOptions();
		options.grabFromProgram(program);
		DecompInterface decompiler = new DecompInterface();
		decompiler.setOptions(options);
		decompiler.toggleCCode(true);
		decompiler.toggleSyntaxTree(true);
		decompiler.setSimplificationStyle("decompile");
		return decompiler;
	}

	private List<String> collectInstructions(Function function) {
		List<String> instructions = new ArrayList<>();
		try {
			AddressSetView body = function.getBody();
			InstructionIterator iterator = currentProgram.getListing().getInstructions(body, true);
			while (iterator.hasNext() && instructions.size() < MAX_INSTRUCTIONS_PER_FUNCTION) {
				Instruction instruction = iterator.next();
				instructions.add(instruction.getAddress() + " " + normalizeText(instruction.toString(), 220));
			}
		}
		catch (Exception ignored) {
		}
		return instructions;
	}

	private void collectCallEdges(Function function, List<Map<String, Object>> edges) {
		if (edges.size() >= MAX_EDGES) {
			return;
		}

		Set<Function> called = function.getCalledFunctions(monitor);
		List<Function> ordered = new ArrayList<>(called);
		Collections.sort(ordered, Comparator.comparing(f -> f.getEntryPoint() == null ? "" : f.getEntryPoint().toString()));
		for (Function target : ordered) {
			if (target == null || edges.size() >= MAX_EDGES) {
				break;
			}
			Map<String, Object> edge = new LinkedHashMap<>();
			edge.put("from", safe(function.getName()));
			edge.put("fromEntry", function.getEntryPoint() == null ? "" : function.getEntryPoint().toString());
			edge.put("to", safe(target.getName()));
			edge.put("toEntry", target.getEntryPoint() == null ? "" : target.getEntryPoint().toString());
			edge.put("external", target.isExternal());
			edges.add(edge);
		}
	}

	private List<String> functionNames(Set<Function> functions, int max) {
		List<String> names = new ArrayList<>();
		List<Function> ordered = new ArrayList<>(functions == null ? Collections.emptySet() : functions);
		Collections.sort(ordered, Comparator.comparing(f -> f.getEntryPoint() == null ? "" : f.getEntryPoint().toString()));
		for (Function function : ordered) {
			if (function == null || names.size() >= max) {
				break;
			}
			names.add(safe(function.getName()));
		}
		return names;
	}

	private List<String> functionFeatureHits(Map<String, Object> item) {
		LinkedHashSet<String> hits = new LinkedHashSet<>();
		String all = (String.valueOf(item.get("name")) + "\n" +
			String.valueOf(item.get("signature")) + "\n" +
			String.valueOf(item.get("called")) + "\n" +
			String.valueOf(item.get("instructions")) + "\n" +
			String.valueOf(item.get("pseudocode"))).toLowerCase(Locale.ROOT);

		if (containsAny(all, "virtualalloc", "virtualprotect", "writeprocessmemory", "createremotethread", "ntcreatethreadex")) {
			hits.add("process-injection-primitives");
		}
		if (containsAny(all, "queueuserapc", "nttestalert", "zwtestalert", "setthreadcontext", "resumethread")) {
			hits.add("apc-or-thread-context-execution");
		}
		if (containsAny(all, "regsetvalue", "runonce", "currentversion\\\\run", "createservice", "schtasks")) {
			hits.add("persistence-primitives");
		}
		if (containsAny(all, "cryptunprotectdata", "minidumpwritedump", "lsass", "sam", "system32\\\\config")) {
			hits.add("credential-or-dump-primitives");
		}
		if (containsAny(all, "winhttp", "internetopen", "httpsendrequest", "connect", "recv", "send")) {
			hits.add("network-command-control-primitives");
		}
		if (containsAny(all, "deletefile", "movefileex", "vssadmin", "bcdedit", "wmic shadowcopy")) {
			hits.add("destructive-or-recovery-impact");
		}
		return new ArrayList<>(hits);
	}

	private Map<String, Object> buildFeatureSummary(Map<String, Object> report, FunctionExportResult functionResult) {
		Map<String, Object> features = new LinkedHashMap<>();
		List<String> hits = new ArrayList<>();
		addImportHits(report, hits);
		addStringHits(report, hits);
		addFunctionHits(functionResult, hits);
		if (functionResult.decompilerError != null && !functionResult.decompilerError.isEmpty()) {
			hits.add("decompiler-error:" + functionResult.decompilerError);
		}

		LinkedHashMap<String, Integer> histogram = new LinkedHashMap<>();
		for (String hit : hits) {
			String key = hit;
			int separator = hit.indexOf(':');
			if (separator > 0) {
				key = hit.substring(0, separator);
			}
			histogram.put(key, histogram.containsKey(key) ? histogram.get(key) + 1 : 1);
		}

		features.put("hits", hits.size() > MAX_FEATURES ? hits.subList(0, MAX_FEATURES) : hits);
		features.put("histogram", histogram);
		return features;
	}

	@SuppressWarnings("unchecked")
	private void addImportHits(Map<String, Object> report, List<String> hits) {
		Object value = report.get("imports");
		if (!(value instanceof List)) {
			return;
		}
		for (Object raw : (List<Object>) value) {
			if (!(raw instanceof Map)) {
				continue;
			}
			Map<String, Object> item = (Map<String, Object>) raw;
			if (Boolean.TRUE.equals(item.get("danger"))) {
				hits.add("dangerous-import:" + item.get("namespace") + "!" + item.get("name"));
			}
		}
	}

	@SuppressWarnings("unchecked")
	private void addStringHits(Map<String, Object> report, List<String> hits) {
		Object value = report.get("strings");
		if (!(value instanceof List)) {
			return;
		}
		for (Object raw : (List<Object>) value) {
			if (!(raw instanceof Map)) {
				continue;
			}
			Map<String, Object> item = (Map<String, Object>) raw;
			if (Boolean.TRUE.equals(item.get("suspicious"))) {
				hits.add("suspicious-string:" + normalizeText(String.valueOf(item.get("value")), 100));
			}
		}
	}

	@SuppressWarnings("unchecked")
	private void addFunctionHits(FunctionExportResult functionResult, List<String> hits) {
		for (Map<String, Object> function : functionResult.functions) {
			Object rawHits = function.get("featureHits");
			if (!(rawHits instanceof List)) {
				continue;
			}
			for (Object raw : (List<Object>) rawHits) {
				hits.add("function-" + raw + ":" + function.get("name"));
			}
		}
	}

	private Map<String, Object> buildLimits(int maxFunctions, int maxDecompilerChars, FunctionExportResult result) {
		Map<String, Object> limits = new LinkedHashMap<>();
		limits.put("maxFunctions", maxFunctions);
		limits.put("maxDecompilerChars", maxDecompilerChars);
		limits.put("exportedFunctions", result.functions.size());
		limits.put("exportedCallEdges", result.edges.size());
		limits.put("decompiledChars", result.decompiledChars);
		limits.put("decompilerError", safe(result.decompilerError));
		limits.put("truncated", result.functions.size() >= maxFunctions || result.decompiledChars >= maxDecompilerChars || result.edges.size() >= MAX_EDGES);
		return limits;
	}

	private boolean matchAny(String value, String[] needles) {
		String text = value == null ? "" : value.toLowerCase(Locale.ROOT);
		for (String needle : needles) {
			if (text.contains(needle.toLowerCase(Locale.ROOT))) {
				return true;
			}
		}
		return false;
	}

	private boolean containsAny(String text, String... needles) {
		String safeText = text == null ? "" : text.toLowerCase(Locale.ROOT);
		for (String needle : needles) {
			if (safeText.contains(needle.toLowerCase(Locale.ROOT))) {
				return true;
			}
		}
		return false;
	}

	private int parseIntArg(String[] args, int index, int fallback, int min, int max) {
		if (args.length <= index) {
			return fallback;
		}
		try {
			int value = Integer.parseInt(args[index]);
			return Math.max(min, Math.min(max, value));
		}
		catch (Exception ignored) {
			return fallback;
		}
	}

	private String safe(String value) {
		return value == null ? "" : value;
	}

	private String normalizeText(String value, int maxChars) {
		if (value == null) {
			return "";
		}
		String normalized = value.replace('\u0000', ' ')
			.replace("\r", "\\r")
			.replace("\n", "\\n")
			.trim();
		return normalized.length() <= maxChars ? normalized : normalized.substring(0, maxChars);
	}

	private String toJson(Object value) {
		StringBuilder builder = new StringBuilder(65536);
		writeJson(builder, value);
		return builder.toString();
	}

	@SuppressWarnings("unchecked")
	private void writeJson(StringBuilder builder, Object value) {
		if (value == null) {
			builder.append("null");
		}
		else if (value instanceof String) {
			writeJsonString(builder, (String) value);
		}
		else if (value instanceof Number || value instanceof Boolean) {
			builder.append(String.valueOf(value));
		}
		else if (value instanceof Map) {
			builder.append('{');
			boolean first = true;
			for (Map.Entry<String, Object> entry : ((Map<String, Object>) value).entrySet()) {
				if (!first) {
					builder.append(',');
				}
				first = false;
				writeJsonString(builder, entry.getKey());
				builder.append(':');
				writeJson(builder, entry.getValue());
			}
			builder.append('}');
		}
		else if (value instanceof Iterable) {
			builder.append('[');
			boolean first = true;
			for (Object item : (Iterable<?>) value) {
				if (!first) {
					builder.append(',');
				}
				first = false;
				writeJson(builder, item);
			}
			builder.append(']');
		}
		else if (value.getClass().isArray()) {
			builder.append('[');
			int length = java.lang.reflect.Array.getLength(value);
			for (int i = 0; i < length; i++) {
				if (i > 0) {
					builder.append(',');
				}
				writeJson(builder, java.lang.reflect.Array.get(value, i));
			}
			builder.append(']');
		}
		else {
			writeJsonString(builder, String.valueOf(value));
		}
	}

	private void writeJsonString(StringBuilder builder, String value) {
		builder.append('"');
		for (int i = 0; i < value.length(); i++) {
			char ch = value.charAt(i);
			switch (ch) {
				case '"':
					builder.append("\\\"");
					break;
				case '\\':
					builder.append("\\\\");
					break;
				case '\b':
					builder.append("\\b");
					break;
				case '\f':
					builder.append("\\f");
					break;
				case '\n':
					builder.append("\\n");
					break;
				case '\r':
					builder.append("\\r");
					break;
				case '\t':
					builder.append("\\t");
					break;
				default:
					if (ch < 0x20) {
						builder.append(String.format("\\u%04x", (int) ch));
					}
					else {
						builder.append(ch);
					}
					break;
			}
		}
		builder.append('"');
	}

	private static final class FunctionExportResult {
		private final List<Map<String, Object>> functions = new ArrayList<>();
		private final List<Map<String, Object>> edges = new ArrayList<>();
		private int decompiledChars;
		private String decompilerError = "";
	}

}
