using ApiAuth.DTO;
using ApiAuth.Entities;
using ApiAuth.Helpers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading.Tasks;

namespace ApiAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class AccountController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public AccountController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpPost("login")]
        //[Authorize(Roles="doctor,admin")]
        [AllowAnonymous]
        public async Task<IActionResult> Login(LoginDTO loginDTO)
        {
            /*
             * Sprawdzamy w bazie danych czy istnieje dany email i czy hasło się zgadza
             * 
             * Jeżeli hasło się nie zgadza zwracamy 400 BadRequest
             * Jeżeli wszystko jest OK to generujemy parę Access Token + Refresh Token
             * 
             */

            JwtSecurityToken token = AuthHelper.GenerateToken(_configuration["Secret"]);
            Guid refreshToken = Guid.NewGuid(); // <- wartość zostaje zapisana do kolumny w tabeli User w rekordzie dla danego usera +
                                                //                                                          dodajemy czas wygaśnięcia (obok)

            return Ok(new
            {
                token = new JwtSecurityTokenHandler().WriteToken(token),
                refreshToken
            });
        }

        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken()
        {
            /*
             * Przyjmujemy w BODY żądania refresh token
             * Sprawdzamy, który użytkownik ma ten token przypisany. Potem sprawdzamy czy token nie wygasł
             * 
             * Jeżeli refresh token wygasł zwracamy 400 BadRequest
             * Jeżeli refresh token NIE wygasł to wtedy generujemy ponownie parę Access Token + Refresh Token
             * 
             * Nowy refresh token nadpisuje stary dla tego użytkownika + ustawiamy mu na nowo datę wygaśnięcia
             * (w kolumnie) 
             * 
             */

            return Ok();
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterDTO registerDTO)
        {
            User user = new User();

            string hashedPassword = new PasswordHasher<User>().HashPassword(user, registerDTO.Password);

            // Dla hasła: 12345678
            // Hash to: AQAAAAEAACcQAAAAEOWK9AnOxpo8DcGIg9ukf+pi+8pLa2ReiQV6/uugipPWlP7gxZS2ASkiN4kMpyGeKg==


            // ================= PONIŻEJ LOGIKA PODCZAS PRZETWARZANIA ŻĄDANIA LOGOWANIA (końcówka /api/account/login) ===================

            // Weryfikacja hasła (tylko na pokaz):
            PasswordVerificationResult verifyPassword = new PasswordHasher<User>()
                .VerifyHashedPassword(user,
                "AQAAAAEAACcQAAAAEOWK9AnOxpo8DcGIg9ukf+pi+8pLa2ReiQV6/uugipPWlP7gxZS2ASkiN4kMpyGeKg==",
                "12345678");

            if(verifyPassword == PasswordVerificationResult.Failed)
            {
                // Hasła nie zgadzają się zwracamy 400 BadRequest
            }

            // Weryfikacja podczas logowania:
            //PasswordVerificationResult verifyPassword = new PasswordHasher<User>()
            //.VerifyHashedPassword(userFromDb, userFromDb.Password, loginDTO.Password);


            return Ok(hashedPassword);
        }
    }
}
