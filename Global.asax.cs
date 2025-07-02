using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Web;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;
using System.Web.Security;

namespace qlthietbi_2
{
    public class MvcApplication : System.Web.HttpApplication
    {
        protected void Application_Start()
        {
            AreaRegistration.RegisterAllAreas();
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            BundleConfig.RegisterBundles(BundleTable.Bundles);
        }
        protected void Application_AuthenticateRequest(object sender, EventArgs e)
        {
            HttpCookie authCookie = Context.Request.Cookies[FormsAuthentication.FormsCookieName];
            if (authCookie != null)
            {
                FormsAuthenticationTicket ticket = FormsAuthentication.Decrypt(authCookie.Value);
                string[] roles = ticket.UserData.Split(','); // có thể dùng nhiều role nếu phân cách bằng dấu ,
                GenericPrincipal userPrincipal = new GenericPrincipal(new GenericIdentity(ticket.Name), roles);
                Context.User = userPrincipal;
            }
        }
        protected void Session_End(object sender, EventArgs e)
        {
            using (var db = new QLThietBiEntities())
            {
                var userId = Session["UserID"] as int?;
                if (userId.HasValue)
                {
                    var lastLogin = db.LoginHistories
                                    .Where(x => x.AccountID == userId && x.LogoutTime == null)
                                    .OrderByDescending(x => x.LoginTime)
                                    .FirstOrDefault();

                    if (lastLogin != null)
                    {
                        lastLogin.LogoutTime = DateTime.Now;
                        db.SaveChanges();
                    }
                }
            }
        }
        protected void Application_Error()
        {
            var exception = Server.GetLastError();

            if (exception is HttpAntiForgeryException)
            {
                Response.Clear();
                Server.ClearError();
                Response.Redirect("~/Account/Login?error=token");
            }
        }
        protected void Session_Start(object sender, EventArgs e)
        {
            // Tăng thời gian timeout
            Session.Timeout = 60;
        }



        protected void Application_PostRequestHandlerExecute(object sender, EventArgs e)
        {
            if (Response.Cookies.Count > 0)
            {
                foreach (string s in Response.Cookies.AllKeys)
                {
                    if (s == FormsAuthentication.FormsCookieName)
                    {
                        Response.Cookies[s].HttpOnly = true;
                        Response.Cookies[s].Secure = FormsAuthentication.RequireSSL;
                        Response.Cookies[s].Path = FormsAuthentication.FormsCookiePath;
                        Response.Cookies[s].Domain = FormsAuthentication.CookieDomain;
                    }
                }
            }
        }



    }

}

