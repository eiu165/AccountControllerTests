using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Web;
using System.Web.Http;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;
using WebMatrix.WebData;

namespace SampleWebApp
{
	// Note: For instructions on enabling IIS6 or IIS7 classic mode, 
	// visit http://go.microsoft.com/?LinkId=9394801

	public class MvcApplication : System.Web.HttpApplication
	{
		protected void Application_Start()
        {
            string connectionString = ConfigurationManager.ConnectionStrings["DefaultConnection"].ToString();
            string providerName = ConfigurationManager.ConnectionStrings["DefaultConnection"].ProviderName;
            //WebSecurity.InitializeDatabaseConnection("DefaultConnection", "UserProfile", "UserId", "UserName", autoCreateTables: true);
            WebSecurity.InitializeDatabaseConnection(connectionString: connectionString, providerName: providerName, userTableName: "UserProfile", userIdColumn: "UserId", userNameColumn: "UserName", autoCreateTables: false);

			AreaRegistration.RegisterAllAreas();

			WebApiConfig.Register(GlobalConfiguration.Configuration);
			FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
			RouteConfig.RegisterRoutes(RouteTable.Routes);
			BundleConfig.RegisterBundles(BundleTable.Bundles);
			AuthConfig.RegisterAuth();
		}
	}
}