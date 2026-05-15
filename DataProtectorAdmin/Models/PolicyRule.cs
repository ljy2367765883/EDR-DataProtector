namespace DataProtectorAdmin.Models
{
    public sealed class PolicyRule
    {
        public PolicyRule(PolicyRuleKind kind, string displayValue, string driverValue)
            : this(kind, displayValue, driverValue, ".dpf")
        {
        }

        public PolicyRule(PolicyRuleKind kind, string displayValue, string driverValue, string extension)
        {
            Kind = kind;
            DisplayValue = displayValue;
            DriverValue = driverValue;
            Extension = extension;
        }

        public PolicyRuleKind Kind { get; private set; }

        public string DisplayValue { get; private set; }

        public string DriverValue { get; private set; }

        public string Extension { get; private set; }
    }
}
