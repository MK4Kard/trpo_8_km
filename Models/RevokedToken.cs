using System;
using System.Collections.Generic;

namespace trpo_8.Models;

public partial class RevokedToken
{
    public int Id { get; set; }

    public string Jti { get; set; } = null!;

    public DateTime ExpiresAt { get; set; }
}
