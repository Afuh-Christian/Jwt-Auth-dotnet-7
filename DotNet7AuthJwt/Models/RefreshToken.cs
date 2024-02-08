﻿namespace DotNet7AuthJwt.Models
{
    public class RefreshToken
    {

        public required string Token { get; set; }
        public DateTime Created { get; set; }
        public DateTime Expires { get; set; }
    }
}
