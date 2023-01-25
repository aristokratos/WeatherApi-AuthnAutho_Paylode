using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using WeatherApi_AuthnAutho.DTO;
using WeatherApi_AuthnAutho.Model;
using WeatherApi_AuthnAutho.Token;
using WeatherApi_AuthnAutho.Services.Interface;

namespace WeatherApi_AuthnAutho.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        //static user object to hold user information
        public static User user = new User();
        //configuration object and user service interface to be injected
        private readonly IConfiguration _configuration;
        private readonly IUserService _userService;

        // constructor to initialize configuration and user service
        public AuthController(IConfiguration configuration, IUserService userService)
        {
            _configuration = configuration;
            _userService = userService;
        }

        //endpoint for authorized user to get their own information

        [HttpGet, Authorize]
        public ActionResult<string> GetMe()
        {
            var userName = _userService.GetMyName();
            return Ok(userName);
        }
        //endpoint for registering a new user
        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto request)
        {
            //hashing and salting of password
            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);
            //setting user information
            user.Username = request.Username;
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;

            return Ok(user);
        }
        //endpoint for user to login
        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserDto request)
        {
            //check if user exists
            if (user.Username != request.Username)
            {
                return BadRequest("User not found.");
            }
            //verifying password
            if (!VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt))
            {
                return BadRequest("Wrong password.");
            }
            //generating token
            string token = CreateToken(user);
            //generating and setting refresh token
            var refreshToken = GenerateRefreshToken();
            SetRefreshToken(refreshToken);

            return Ok(token);
        }
        //endpoint for refreshing token
        [HttpPost("refresh-token")]
        public async Task<ActionResult<string>> RefreshToken()
        {
            //getting refresh token from cookies
            var refreshToken = Request.Cookies["refreshToken"];
            //validating refresh token
            if (!user.RefreshToken.Equals(refreshToken))
            {
                return Unauthorized("Invalid Refresh Token.");
            }
            else if (user.TokenExpires < DateTime.Now)
            {
                return Unauthorized("Token expired.");
            }

            string token = CreateToken(user);
            var newRefreshToken = GenerateRefreshToken();
            SetRefreshToken(newRefreshToken);

            return Ok(token);
        }

        private RefreshToken GenerateRefreshToken()
        {
            //generate a new refresh token
            var refreshToken = new RefreshToken
            {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                Expires = DateTime.Now.AddDays(7),
                Created = DateTime.Now
            };

            return refreshToken;
        }

        private void SetRefreshToken(RefreshToken newRefreshToken)
        {
            //set the new refresh token in cookies
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = newRefreshToken.Expires
            };
            Response.Cookies.Append("refreshToken", newRefreshToken.Token, cookieOptions);
            //update user's refresh token information
            user.RefreshToken = newRefreshToken.Token;
            user.TokenCreated = newRefreshToken.Created;
            user.TokenExpires = newRefreshToken.Expires;
        }

        private string CreateToken(User user)
        {
            //adding claims to token
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Role, "Admin")
            };
            //setting key for token
            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(("AppSettings:Token")));
            //signing the token
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: creds);

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            //hashing and salting password
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            //verifying hashed password
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }
        }
    }
}
