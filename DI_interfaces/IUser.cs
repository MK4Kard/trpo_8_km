namespace trpo_8.DI_interfaces
{
    public interface IUser
    {
        int Id { get; }
        string Login { get; }
        string Role { get; }
        string PasswordHash { get; }
    }
}
