using System.Security.Claims;
using WeatherApi_AuthnAutho.Services.Interface;

namespace WeatherApi_AuthnAutho.Services.UserService
{
    public class UserService : IUserService
    {
        //access to httpcontext
        private readonly IHttpContextAccessor _httpContextAccessor;

        public UserService(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }
        //Getting name of the authorized user

        public string GetMyName()
        {
            //checking if the httpcontext is not null
            var result = string.Empty;
            if (_httpContextAccessor.HttpContext != null)
            {
                //getting name of the user from claims
                result = _httpContextAccessor.HttpContext.User.FindFirstValue(ClaimTypes.Name);
            }
            return result;
        }
    }
}
