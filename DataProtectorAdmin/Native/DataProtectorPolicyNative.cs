using System.Runtime.InteropServices;
using System.Text;

namespace DataProtectorAdmin.Native
{
    internal static class DataProtectorPolicyNative
    {
        private const string DllName = "DataProtectorPolicyApi.dll";

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyCheckConnection();

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyAddProcessNameRule(string processName);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyAddProcessNameRuleEx(string processName, string extension);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyRemoveProcessNameRule(string processName);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyRemoveProcessNameRuleEx(string processName, string extension);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyAddProcessDirectoryRule(string directoryPath);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyAddProcessDirectoryRuleEx(string directoryPath, string extension);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyRemoveProcessDirectoryRule(string directoryPath);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyRemoveProcessDirectoryRuleEx(string directoryPath, string extension);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyClearProcessRules();

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyQueryProcessRules(
            [Out] NativePolicyRule[] rules,
            uint ruleCapacity,
            out uint ruleCount,
            System.IntPtr stringBuffer,
            uint stringBufferChars,
            out uint stringBufferCharsRequired);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyConvertDosPathToNtPath(
            string dosPath,
            StringBuilder ntPath,
            uint ntPathChars);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyGetLastErrorMessage(
            StringBuilder buffer,
            uint bufferChars);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct NativePolicyRule
        {
            public uint RuleType;
            public System.IntPtr Value;
            public System.IntPtr Extension;
        }
    }
}
