using trpo_8.DI_interfaces;

namespace trpo_8.Models;

public class RefreshToken : IRefreshToken
{
    public int Id { get; set; }

    public int UserId { get; set; }

    public string TokenHash { get; set; } = null!;

    public DateTime ExpiresAt { get; set; }

    public virtual User User { get; set; } = null!;
}
