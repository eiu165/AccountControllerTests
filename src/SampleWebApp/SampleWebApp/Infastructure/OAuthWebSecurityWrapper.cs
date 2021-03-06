namespace SampleWebApp.Infastructure
{
	using System.Collections.Generic;
	using DotNetOpenAuth.AspNet;
	using Microsoft.Web.WebPages.OAuth;
    using SampleWebApp.Business;

	public class OAuthWebSecurityWrapper : IOAuthWebSecurity
	{
		public string GetUserName(string providerName, string providerUserId)
		{
			return OAuthWebSecurity.GetUserName(providerName, providerUserId);
		}

		public bool HasLocalAccount(int userId)
		{
			return OAuthWebSecurity.HasLocalAccount(userId);
		}

		public ICollection<OAuthAccount> GetAccountsFromUserName(string userName)
		{
			return OAuthWebSecurity.GetAccountsFromUserName(userName);
		}

		public bool DeleteAccount(string providerName, string providerUserId)
		{
			return OAuthWebSecurity.DeleteAccount(providerName, providerUserId);
		}

		public AuthenticationResult VerifyAuthentication(string returnUrl)
		{
			return OAuthWebSecurity.VerifyAuthentication(returnUrl);
		}

		public bool Login(string providerName, string providerUserId, bool createPersistentCookie)
		{
			return OAuthWebSecurity.Login(providerName, providerUserId, createPersistentCookie);
		}

		public void CreateOrUpdateAccount(string providerName, string providerUserId, string userName)
		{
			OAuthWebSecurity.CreateOrUpdateAccount(providerName, providerUserId, userName);
		}

		public string SerializeProviderUserId(string providerName, string providerUserId)
		{
			return OAuthWebSecurity.SerializeProviderUserId(providerName, providerUserId);
		}

		public AuthenticationClientData GetOAuthClientData(string providerName)
		{
			return OAuthWebSecurity.GetOAuthClientData(providerName);
		}

		public bool TryDeserializeProviderUserId(string data, out string providerName, out string providerUserId)
		{
			return OAuthWebSecurity.TryDeserializeProviderUserId(data, out providerName, out providerUserId);
		}

		public ICollection<AuthenticationClientData> RegisteredClientData { get { return OAuthWebSecurity.RegisteredClientData; } }

		public void RequestAuthentication(string provider, string returnUrl)
		{
			OAuthWebSecurity.RequestAuthentication(provider, returnUrl);
		}
	}
}