using System;
using System.Collections.Generic;
using trpo_8.DI_interfaces;

namespace trpo_8.Models;

public class User : IUser
{
    public int Id { get; set; }

    public string Login { get; set; } = null!;

    public string Role { get; set; } = null!;

    public string PasswordHash { get; set; } = null!;

    public virtual ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
}
