using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.Security.Authentication.Web;
using Newtonsoft.Json;
using RestSharp;

namespace SpotifyTutorial.Services
{
    public static class SpotifyService
    {
        private const string ClientId = "CLIENT_ID";
        private const string ClientSecret = "CLIENT_SECRET";

        private static readonly Uri RedirectUri = new Uri("https://example.com/callback/");
        private static readonly Uri AccountUri = new Uri("https://accounts.spotify.com/");
        private static readonly Uri ApiUri = new Uri("https://api.spotify.com/");

        /// <summary>
        /// Launch the Web Authentication Broker and prompt user to login for access token and refresh token
        /// </summary>
        public static async void LoginSpotify()
        {
            var client = new RestClient()
            {
                BaseUrl = AccountUri,
                Timeout = 5000
            };

            var loginRequest = new RestRequest("authorize", Method.GET);
            loginRequest.AddParameter("client_id", ClientId);
            loginRequest.AddParameter("response_type", "code");
            loginRequest.AddParameter("redirect_uri", RedirectUri.ToString());

            var loginUri = client.Execute(loginRequest).ResponseUri;

            var result = "";

            try
            {
                var webAuthenticationResult = await WebAuthenticationBroker.AuthenticateAsync(
                    Windows.Security.Authentication.Web.WebAuthenticationOptions.None, loginUri, RedirectUri);
                switch (webAuthenticationResult.ResponseStatus)
                {
                    case WebAuthenticationStatus.Success:
                        result = webAuthenticationResult.ResponseData.ToString();
                        break;
                    case WebAuthenticationStatus.ErrorHttp:
                        result = webAuthenticationResult.ResponseErrorDetail.ToString();
                        break;
                    case WebAuthenticationStatus.UserCancel:
                        result = "Login Canceled";
                        break;
                    default:
                        result = webAuthenticationResult.ResponseData.ToString();
                        break;
                }
            }
            catch (Exception e)
            {
                result = e.Message;
            }

            Debug.WriteLine(result);

            var authenticationCode = "";
            if (result.Contains("https://example.com/callback/"))
            {
                authenticationCode = result.Remove(0, RedirectUri.ToString().Length + 6);
                Debug.WriteLine(authenticationCode);
            }
            else
            {
                authenticationCode = string.Empty;
                //TODO: Handle the error where login is not successful.
            }

            if (string.IsNullOrEmpty(authenticationCode)) return;
            var accessTokenRequest = new RestRequest("api/token", Method.POST);

            var idSecretPair = $"{ClientId}:{ClientSecret}";
            var requestHeader = $"Basic {Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(idSecretPair))}";
                

            accessTokenRequest.AddHeader("Authorization", requestHeader);

            accessTokenRequest.AddParameter("grant_type", "authorization_code");
            accessTokenRequest.AddParameter("code", authenticationCode);
            accessTokenRequest.AddParameter("redirect_uri", RedirectUri.ToString());

            var accessTokenResponse = client.Execute(accessTokenRequest);

            Debug.WriteLine(accessTokenResponse.StatusCode);
            Debug.WriteLine(accessTokenResponse.Content);

            var credentialDetials = JsonConvert.DeserializeObject<SpotifyCredential>(accessTokenResponse.Content);
            //TODO: Save the spotify credentials to device for further consumption
        }

        public class SpotifyCredential
        {
            [JsonProperty(PropertyName = "access_token")]
            public string AccessToken { get; set; }

            [JsonProperty(PropertyName = "token_type")]
            public string TokenType { get; set; }

            [JsonProperty(PropertyName = "scope")]
            public string Scope { get; set; }

            [JsonProperty(PropertyName = "expires_in")]
            public int ExpiresIn { get; set; }

            [JsonProperty(PropertyName = "refresh_token")]
            public string RefreshToken { get; set; }
        }
    }
}
