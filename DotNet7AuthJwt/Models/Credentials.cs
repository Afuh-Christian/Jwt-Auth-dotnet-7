namespace DotNet7AuthJwt.Models;

public class Credentials
{
public string? Username { get; set; } = string.Empty;
public List<string>? Roles { get; set; } = new List<string>();

}
