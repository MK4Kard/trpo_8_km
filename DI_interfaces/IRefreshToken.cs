namespace trpo_8.DI_interfaces
{
    public interface IRefreshToken
    {
        int Id { get; }
        int UserId { get; }
        string TokenHash { get; }
        DateTime ExpiresAt { get; }
    }
}
