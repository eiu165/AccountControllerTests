using System;
using System.Collections.Generic;
using System.Linq;
using System.Transactions;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;
using DotNetOpenAuth.AspNet;
using Microsoft.Web.WebPages.OAuth;
using WebMatrix.WebData;
using SampleWebApp.Filters;
using SampleWebApp.Models;

namespace SampleWebApp.Controllers
{
	[Authorize]
	[InitializeSimpleMembership]
	public class AccountController : Controller
	{
		private IWebSecurity _webSecurity { get; set; }
		private IOAuthWebSecurity _oAuthWebSecurity { get; set; }

		public AccountController()
			: this(new WebSecurityWrapper(), new OAuthWebSecurityWrapper())
		{
		}

		public AccountController(IWebSecurity webSecurity, IOAuthWebSecurity oAuthWebSecurity)
		{
			_webSecurity = webSecurity;
			_oAuthWebSecurity = oAuthWebSecurity;
		}

		//
		// GET: /Account/Login

		[AllowAnonymous]
		public ActionResult Login(string returnUrl)
		{
			ViewBag.ReturnUrl = returnUrl;
			return View();
		}

		//
		// POST: /Account/Login

		[HttpPost]
		[AllowAnonymous]
		[ValidateAntiForgeryToken]
		public ActionResult Login(LoginViewModel model, string returnUrl)
		{
			if (ModelState.IsValid && _webSecurity.Login(model.UserName, model.Password, persistCookie: model.RememberMe))
			{
				return RedirectToLocal(returnUrl);
			}

			// If we got this far, something failed, redisplay form
			ModelState.AddModelError("", "The user name or password provided is incorrect.");
			return View(model);
		}

		//
		// POST: /Account/LogOff

		[HttpPost]
		[ValidateAntiForgeryToken]
		public ActionResult LogOff()
		{
			_webSecurity.Logout();

			return RedirectToAction("Index", "Home");
		}

		//
		// GET: /Account/Register

		[AllowAnonymous]
		public ActionResult Register()
		{
			return View();
		}

		//
		// POST: /Account/Register

		[HttpPost]
		[AllowAnonymous]
		[ValidateAntiForgeryToken]
		public ActionResult Register(RegisterViewModel model)
		{
			if (ModelState.IsValid)
			{
				// Attempt to register the user
				try
				{
					_webSecurity.CreateUserAndAccount(model.UserName, model.Password);
					_webSecurity.Login(model.UserName, model.Password);
					return RedirectToAction("Index", "Home");
				}
				catch (MembershipCreateUserException e)
				{
					ModelState.AddModelError("", ErrorCodeToString(e.StatusCode));
				}
			}

			// If we got this far, something failed, redisplay form
			return View(model);
		}

		//
		// POST: /Account/Disassociate

		[HttpPost]
		[ValidateAntiForgeryToken]
		public ActionResult Disassociate(string provider, string providerUserId)
		{
			string ownerAccount = _oAuthWebSecurity.GetUserName(provider, providerUserId);
			ManageMessageId? message = null;

			// Only disassociate the account if the currently logged in user is the owner
			if (ownerAccount == _webSecurity.CurrentUser.Identity.Name)
			{
				// Use a transaction to prevent the user from deleting their last login credential
				using (var scope = new TransactionScope(TransactionScopeOption.Required, new TransactionOptions { IsolationLevel = IsolationLevel.Serializable }))
				{
					bool hasLocalAccount = _oAuthWebSecurity.HasLocalAccount(_webSecurity.GetUserId(_webSecurity.CurrentUser.Identity.Name));
					if (hasLocalAccount || _oAuthWebSecurity.GetAccountsFromUserName(_webSecurity.CurrentUser.Identity.Name).Count > 1)
					{
						_oAuthWebSecurity.DeleteAccount(provider, providerUserId);
						scope.Complete();
						message = ManageMessageId.RemoveLoginSuccess;
					}
				}
			}

			return RedirectToAction("Manage", new { Message = message });
		}

		//
		// GET: /Account/Manage

		public ActionResult Manage(ManageMessageId? message)
		{
			ViewBag.StatusMessage =
				message == ManageMessageId.ChangePasswordSuccess ? "Your password has been changed."
				: message == ManageMessageId.SetPasswordSuccess ? "Your password has been set."
				: message == ManageMessageId.RemoveLoginSuccess ? "The external login was removed."
				: "";
			ViewBag.HasLocalPassword = _oAuthWebSecurity.HasLocalAccount(_webSecurity.GetUserId(_webSecurity.CurrentUser.Identity.Name));
			ViewBag.ReturnUrl = Url.Action("Manage");
			return View();
		}

		//
		// POST: /Account/Manage

		[HttpPost]
		[ValidateAntiForgeryToken]
		public ActionResult Manage(LocalPasswordViewModel model)
		{
			bool hasLocalAccount = _oAuthWebSecurity.HasLocalAccount(_webSecurity.GetUserId(_webSecurity.CurrentUser.Identity.Name));
			ViewBag.HasLocalPassword = hasLocalAccount;
			ViewBag.ReturnUrl = Url.Action("Manage");
			if (hasLocalAccount)
			{
				if (ModelState.IsValid)
				{
					// ChangePassword will throw an exception rather than return false in certain failure scenarios.
					bool changePasswordSucceeded;
					try
					{
						changePasswordSucceeded = _webSecurity.ChangePassword(_webSecurity.CurrentUser.Identity.Name, model.OldPassword, model.NewPassword);
					}
					catch (Exception)
					{
						changePasswordSucceeded = false;
					}

					if (changePasswordSucceeded)
					{
						return RedirectToAction("Manage", new { Message = ManageMessageId.ChangePasswordSuccess });
					}
					else
					{
						ModelState.AddModelError("", "The current password is incorrect or the new password is invalid.");
					}
				}
			}
			else
			{
				// User does not have a local password so remove any validation errors caused by a missing
				// OldPassword field
				ModelState state = ModelState["OldPassword"];
				if (state != null)
				{
					state.Errors.Clear();
				}

				if (ModelState.IsValid)
				{
					try
					{
						_webSecurity.CreateAccount(_webSecurity.CurrentUser.Identity.Name, model.NewPassword);
						return RedirectToAction("Manage", new { Message = ManageMessageId.SetPasswordSuccess });
					}
					catch (Exception e)
					{
						ModelState.AddModelError("", e);
					}
				}
			}

			// If we got this far, something failed, redisplay form
			return View(model);
		}

		//
		// POST: /Account/ExternalLogin

		[HttpPost]
		[AllowAnonymous]
		[ValidateAntiForgeryToken]
		public ActionResult ExternalLogin(string provider, string returnUrl)
		{
			return new ExternalLoginResult(provider, Url.Action("ExternalLoginCallback", new { ReturnUrl = returnUrl }), this._oAuthWebSecurity);
		}

		//
		// GET: /Account/ExternalLoginCallback

		[AllowAnonymous]
		public ActionResult ExternalLoginCallback(string returnUrl)
		{
			AuthenticationResult result = _oAuthWebSecurity.VerifyAuthentication(Url.Action("ExternalLoginCallback", new { ReturnUrl = returnUrl }));
			if (!result.IsSuccessful)
			{
				return RedirectToAction("ExternalLoginFailure");
			}

			if (_oAuthWebSecurity.Login(result.Provider, result.ProviderUserId, createPersistentCookie: false))
			{
				return RedirectToLocal(returnUrl);
			}

			if (_webSecurity.CurrentUser.Identity.IsAuthenticated)
			{
				// If the current user is logged in add the new account
				_oAuthWebSecurity.CreateOrUpdateAccount(result.Provider, result.ProviderUserId, _webSecurity.CurrentUser.Identity.Name);
				return RedirectToLocal(returnUrl);
			}
			else
			{
				// User is new, ask for their desired membership name
				string loginData = _oAuthWebSecurity.SerializeProviderUserId(result.Provider, result.ProviderUserId);
				ViewBag.ProviderDisplayName = _oAuthWebSecurity.GetOAuthClientData(result.Provider).DisplayName;
				ViewBag.ReturnUrl = returnUrl;
				return View("ExternalLoginConfirmation", new RegisterExternalLoginViewModel { UserName = result.UserName, ExternalLoginData = loginData });
			}
		}

		//
		// POST: /Account/ExternalLoginConfirmation

		[HttpPost]
		[AllowAnonymous]
		[ValidateAntiForgeryToken]
		public ActionResult ExternalLoginConfirmation(RegisterExternalLoginViewModel model, string returnUrl)
		{
			string provider = null;
			string providerUserId = null;

			if (_webSecurity.CurrentUser.Identity.IsAuthenticated || !_oAuthWebSecurity.TryDeserializeProviderUserId(model.ExternalLoginData, out provider, out providerUserId))
			{
				return RedirectToAction("Manage");
			}

			if (ModelState.IsValid)
			{
				// Insert a new user into the database
				using (UsersContext db = new UsersContext())
				{
					UserProfile user = db.UserProfiles.FirstOrDefault(u => u.UserName.ToLower() == model.UserName.ToLower());
					// Check if user already exists
					if (user == null)
					{
						// Insert name into the profile table
						db.UserProfiles.Add(new UserProfile { UserName = model.UserName });
						db.SaveChanges();

						_oAuthWebSecurity.CreateOrUpdateAccount(provider, providerUserId, model.UserName);
						_oAuthWebSecurity.Login(provider, providerUserId, createPersistentCookie: false);

						return RedirectToLocal(returnUrl);
					}
					else
					{
						ModelState.AddModelError("UserName", "User name already exists. Please enter a different user name.");
					}
				}
			}

			ViewBag.ProviderDisplayName = _oAuthWebSecurity.GetOAuthClientData(provider).DisplayName;
			ViewBag.ReturnUrl = returnUrl;
			return View(model);
		}

		//
		// GET: /Account/ExternalLoginFailure

		[AllowAnonymous]
		public ActionResult ExternalLoginFailure()
		{
			return View();
		}

		[AllowAnonymous]
		[ChildActionOnly]
		public ActionResult ExternalLoginsList(string returnUrl)
		{
			ViewBag.ReturnUrl = returnUrl;
			return PartialView("_ExternalLoginsListPartial", _oAuthWebSecurity.RegisteredClientData);
		}

		[ChildActionOnly]
		public ActionResult RemoveExternalLogins()
		{
			ICollection<OAuthAccount> accounts = _oAuthWebSecurity.GetAccountsFromUserName(_webSecurity.CurrentUser.Identity.Name);
			List<ExternalLoginViewModel> externalLogins = new List<ExternalLoginViewModel>();
			foreach (OAuthAccount account in accounts)
			{
				AuthenticationClientData clientData = _oAuthWebSecurity.GetOAuthClientData(account.Provider);

				externalLogins.Add(new ExternalLoginViewModel
				{
					Provider = account.Provider,
					ProviderDisplayName = clientData.DisplayName,
					ProviderUserId = account.ProviderUserId,
				});
			}

			ViewBag.ShowRemoveButton = externalLogins.Count > 1 || _oAuthWebSecurity.HasLocalAccount(_webSecurity.GetUserId(_webSecurity.CurrentUser.Identity.Name));
			return PartialView("_RemoveExternalLoginsPartial", externalLogins);
		}

		#region Helpers
		private ActionResult RedirectToLocal(string returnUrl)
		{
			if (Url.IsLocalUrl(returnUrl))
			{
				return Redirect(returnUrl);
			}
			else
			{
				return RedirectToAction("Index", "Home");
			}
		}

		public enum ManageMessageId
		{
			ChangePasswordSuccess,
			SetPasswordSuccess,
			RemoveLoginSuccess,
		}

		internal class ExternalLoginResult : ActionResult
		{
			public ExternalLoginResult(string provider, string returnUrl, IOAuthWebSecurity oAuthWebSecurity)
			{
				Provider = provider;
				ReturnUrl = returnUrl;
				OAuthWebSecurity = oAuthWebSecurity;
			}

			public string Provider { get; private set; }
			public string ReturnUrl { get; private set; }
			public IOAuthWebSecurity OAuthWebSecurity { get; private set; }

			public override void ExecuteResult(ControllerContext context)
			{
				OAuthWebSecurity.RequestAuthentication(Provider, ReturnUrl);
			}
		}

		private static string ErrorCodeToString(MembershipCreateStatus createStatus)
		{
			// See http://go.microsoft.com/fwlink/?LinkID=177550 for
			// a full list of status codes.
			switch (createStatus)
			{
				case MembershipCreateStatus.DuplicateUserName:
					return "User name already exists. Please enter a different user name.";

				case MembershipCreateStatus.DuplicateEmail:
					return "A user name for that e-mail address already exists. Please enter a different e-mail address.";

				case MembershipCreateStatus.InvalidPassword:
					return "The password provided is invalid. Please enter a valid password value.";

				case MembershipCreateStatus.InvalidEmail:
					return "The e-mail address provided is invalid. Please check the value and try again.";

				case MembershipCreateStatus.InvalidAnswer:
					return "The password retrieval answer provided is invalid. Please check the value and try again.";

				case MembershipCreateStatus.InvalidQuestion:
					return "The password retrieval question provided is invalid. Please check the value and try again.";

				case MembershipCreateStatus.InvalidUserName:
					return "The user name provided is invalid. Please check the value and try again.";

				case MembershipCreateStatus.ProviderError:
					return "The authentication provider returned an error. Please verify your entry and try again. If the problem persists, please contact your system administrator.";

				case MembershipCreateStatus.UserRejected:
					return "The user creation request has been canceled. Please verify your entry and try again. If the problem persists, please contact your system administrator.";

				default:
					return "An unknown error occurred. Please verify your entry and try again. If the problem persists, please contact your system administrator.";
			}
		}
		#endregion
	}
}
