namespace DataProtectorAdmin.Models
{
    public sealed class PolicyOperationResult
    {
        public PolicyOperationResult(bool succeeded, uint status, string message)
        {
            Succeeded = succeeded;
            Status = status;
            Message = message;
        }

        public bool Succeeded { get; private set; }

        public uint Status { get; private set; }

        public string Message { get; private set; }

        public static PolicyOperationResult Success(string message)
        {
            return new PolicyOperationResult(true, 0, message);
        }
    }
}
