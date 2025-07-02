using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace qlthietbi_2.Controllers
{
    public class BaseController : Controller
    {
        protected string CurrentUserRole => Session["UserRole"]?.ToString();

        protected ActionResult RedirectIfNotAdmin()
        {
            if (CurrentUserRole != "Admin")
            {
                TempData["ErrorMessage"] = "Bạn không có quyền truy cập!";
                return RedirectToAction("Index", "Home");
            }
            return null;
        }
    }
}