using qlthietbi_2.Models;
using qlthietbi_2.ViewModels;
using System;
using System.Collections.Generic;
using System.Data.Entity.Validation;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Web;
using System.Web.Helpers;
using System.Web.Mvc;
using System.Web.Security;
namespace qlthietbi_2.Controllers
{
    public class AccountController : Controller
    {
        public ActionResult Index()
        {
            using (QLThietBiEntities db = new QLThietBiEntities())
            {
                var accounts = db.Accounts.ToList();
                return View(accounts);
            }
        }
        [AllowAnonymous]
        public ActionResult Login()
        {
            Session.Clear();
            Session.Abandon();
            FormsAuthentication.SignOut();

            return View();
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Login(Account account)
        {
            if (account == null)
            {
                ModelState.AddModelError("", "Dữ liệu không hợp lệ.");
                return View();
            }

            if (!ModelState.IsValid)
            {
                return View(account);
            }

            using (QLThietBiEntities db = new QLThietBiEntities())
            {
                var user = db.Accounts.FirstOrDefault(a => a.Username == account.Username
                                                       && a.Password == account.Password);

                if (user == null)
                {
                    ModelState.AddModelError("", "Tên đăng nhập hoặc mật khẩu không đúng.");
                    return View(account);
                }

                var ipAddress = GetClientIP(Request);
                System.Diagnostics.Debug.WriteLine($"IP detected: {ipAddress}");

                db.LoginHistories.Add(new LoginHistory
                {
                    AccountID = user.AccountID,
                    LoginTime = DateTime.Now,
                    IPAddress = ipAddress
                });
                db.SaveChanges();

                Session["UserID"] = user.AccountID;
                Session["Username"] = user.Username;
                Session["UserRole"] = user.Role;

                var authTicket = new FormsAuthenticationTicket(
                    version: 1,
                    name: user.Username,
                    issueDate: DateTime.Now,
                    expiration: DateTime.Now.AddMinutes(30),
                    isPersistent: false,
                    userData: user.Role
                );

                string encryptedTicket = FormsAuthentication.Encrypt(authTicket);
                var authCookie = new HttpCookie(FormsAuthentication.FormsCookieName, encryptedTicket)
                {
                    HttpOnly = true,
                    Secure = FormsAuthentication.RequireSSL
                };
                Response.Cookies.Add(authCookie);

                try
                {
                    string oldCookieToken = Request.Cookies["__RequestVerificationToken"]?.Value;
                    string newCookieToken, newFormToken;
                    AntiForgery.GetTokens(oldCookieToken, out newCookieToken, out newFormToken);

                    var antiForgeryCookie = new HttpCookie("__RequestVerificationToken", newCookieToken)
                    {
                        HttpOnly = true,
                        Secure = Request.IsSecureConnection
                    };
                    Response.Cookies.Set(antiForgeryCookie);
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Lỗi anti-forgery token: {ex.Message}");
                }

                return RedirectToAction("Index", "Main");
            }
        }
        public static string GetClientIP(HttpRequestBase request)
        {
            string ip = request.Headers["X-Forwarded-For"];

            if (string.IsNullOrEmpty(ip))
            {
                ip = request.Headers["HTTP_X_FORWARDED_FOR"];
            }

            if (string.IsNullOrEmpty(ip))
            {
                ip = request.UserHostAddress;
            }

            // Fallback to HttpContext.Current if still empty (for some edge cases)
            if (string.IsNullOrEmpty(ip))
            {
                if (System.Web.HttpContext.Current != null)
                {
                    ip = System.Web.HttpContext.Current.Request.UserHostAddress;
                }
            }

            // Handle multiple IPs (if behind proxy)
            if (!string.IsNullOrEmpty(ip) && ip.Contains(","))
            {
                ip = ip.Split(',')[0].Trim();
            }

            return !string.IsNullOrEmpty(ip) ? ip : "N/A";
        }

        public ActionResult Logout()
        {
            using (var db = new QLThietBiEntities())
            {
                var userId = (int)Session["UserID"];
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

            Session.Clear();
            Session.Abandon();
            FormsAuthentication.SignOut();

            return RedirectToAction("Login");
        }
        public ActionResult Register()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Register(qlthietbi_2.ViewModels.AccountViewModel model)
        {
            if (ModelState.IsValid)
            {
                using (var db = new QLThietBiEntities())
                {
                    bool isUsernameTaken = db.Accounts.Any(a => a.Username == model.Username);
                    if (isUsernameTaken)
                    {
                        ModelState.AddModelError("Username", "Username đã tồn tại.");
                        return View(model);
                    }

                    bool isEmailTaken = db.Accounts.Any(a => a.Email == model.Email);
                    if (isEmailTaken)
                    {
                        ModelState.AddModelError("Email", "Email đã được sử dụng.");
                        return View(model);
                    }

                    var newAccount = new qlthietbi_2.Account
                    {
                        Username = model.Username?.Trim(),
                        Email = model.Email?.Trim(),
                        Password = model.Password,  
                        Role = "User"
                    };

                    db.Accounts.Add(newAccount);

                    try
                    {
                        db.SaveChanges();
                        return RedirectToAction("Login", "Account");
                    }
                    catch (DbEntityValidationException ex)
                    {
                        foreach (var validationErrors in ex.EntityValidationErrors)
                        {
                            foreach (var validationError in validationErrors.ValidationErrors)
                            {
                                ModelState.AddModelError(validationError.PropertyName, validationError.ErrorMessage);
                            }
                        }
                    }
                }
            }


            return View(model);
        }


        public ActionResult ForgotPasswordView()
        {
            return View();
        }

        public ActionResult ForgotPassword(string email)
        {
            using (var db = new QLThietBiEntities())
            {
                var user = db.Accounts.FirstOrDefault(u => u.Email == email);
                if (user == null)
                {
                    ViewBag.Message = "Email không tồn tại trong hệ thống.";
                    return View("ForgotPasswordView");
                }

                // 2. Tạo mã OTP
                var otp = new Random().Next(100000, 999999).ToString();

                Session["ResetEmail"] = email;
                Session["OTP"] = otp;
                Session["User"] = user;

                EmailService.Send(email, "Mã OTP đặt lại mật khẩu", $"Mã OTP của bạn là: {otp}");
                TempData["SuccessMessage"] = "Mã OTP đã được gửi đến email của bạn.";
                return RedirectToAction("ResetPassword");
            }
        }
        [HttpPost]
        public ActionResult ResetPasswordConfirm(string otp, string newPassword)
        {
            var sessionOtp = Session["OTP"] as string;
            var email = Session["ResetEmail"] as string;
            QLThietBiEntities db = new QLThietBiEntities();

            if (sessionOtp == null || email == null)
            {
                ViewBag.Message = "Phiên làm việc đã hết hạn. Vui lòng thử lại.";
                return View("ResetPassword");
            }

            if (otp != sessionOtp)
            {
                ViewBag.Message = "Mã OTP không đúng.";
                return View("ResetPassword");
            }

            var user = db.Accounts.FirstOrDefault(u => u.Email == email);
            if (user != null)
            {
                user.Password = newPassword; // Gợi ý: nên hash mật khẩu
                db.SaveChanges();

                Session["OTP"] = null;
                Session["ResetEmail"] = null;

                TempData["SuccessMessage"] = "Đặt lại mật khẩu thành công!";
                return RedirectToAction("Login");
            }
            else
            {
                ViewBag.Message = "Không tìm thấy người dùng.";
                return View("ResetPassword");
            }
        }


        public ActionResult ResetPassword()
        {
            return View();
        }
        public static class EmailService
        {
            public static void Send(string to, string subject, string body)
            {
                var fromAddress = new MailAddress("ntthinh29@gmail.com", "QUẢN LÝ THIẾT BỊ");
                var toAddress = new MailAddress(to);
                const string fromPassword = "qhgx brst plbb qddh\r\n"; // KHÔNG dùng mật khẩu Gmail thường

                var smtp = new SmtpClient
                {
                    Host = "smtp.gmail.com",
                    Port = 587,
                    EnableSsl = true,
                    DeliveryMethod = SmtpDeliveryMethod.Network,
                    UseDefaultCredentials = false,
                    Credentials = new NetworkCredential(fromAddress.Address, fromPassword)
                };

                using (var message = new MailMessage(fromAddress, toAddress)
                {
                    Subject = subject,
                    Body = body
                })
                {
                    smtp.Send(message);
                }
            }
        }

        [HttpPost]
        public ActionResult TrackBrowserClose()
        {
            if (User.Identity.IsAuthenticated)
            {
                var userId = int.Parse(((FormsIdentity)User.Identity).Ticket.UserData);

                using (var db = new QLThietBiEntities())
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
            return Json(new { success = true });
        }



        public AccountController() : this(new QLThietBiEntities())
        {
        }
        private readonly QLThietBiEntities _context;

        public AccountController(QLThietBiEntities context)
        {
            _context = context;
        }
        [Authorize(Roles = "Admin,User")]
        [HttpGet]
        public ActionResult EditProfile()
        {
            var currentUsername = User.Identity.Name;
            using (var db = new QLThietBiEntities())
            {
                var user = db.Accounts.FirstOrDefault(a => a.Username == currentUsername);
                if (user == null)
                {
                    TempData["ErrorMessage"] = "Không tìm thấy tài khoản";
                    return RedirectToAction("Profile");
                }

                var model = new AccountViewModel
                {
                    AccountID = user.AccountID,
                    Username = user.Username,
                    Email = user.Email,
                    Role = user.Role
                };

                return View(model);
            }
        }
        [Authorize(Roles = "Admin,User")]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult EditProfile(AccountViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            using (var db = new QLThietBiEntities())
            {
                var account = db.Accounts.Find(model.AccountID);
                if (account == null)
                {
                    TempData["ErrorMessage"] = "Tài khoản không tồn tại";
                    return RedirectToAction("Profile");
                }

                account.Email = model.Email;

                if (!string.IsNullOrEmpty(model.Password))
                {
                    account.Password = model.Password; 
                                                       
                }

                db.SaveChanges();

                TempData["SuccessMessage"] = "Cập nhật thông tin thành công";
                
                return RedirectToAction("EditProfile");
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin,User")]
        public JsonResult DeleteAccount(string password)
        {
            try
            {
                if (!User.Identity.IsAuthenticated)
                {
                    return Json(new { success = false, message = "Người dùng chưa đăng nhập" });
                }

                var currentUsername = User.Identity.Name;

                using (var db = new QLThietBiEntities())
                {
                    var user = db.Accounts.FirstOrDefault(a => a.Username == currentUsername);
                    if (user == null)
                    {
                        return Json(new { success = false, message = "Không tìm thấy tài khoản" });
                    }

                    if (user.Password != password)
                    {
                        return Json(new { success = false, message = "Mật khẩu không chính xác" });
                    }

                    if (user.Role == "Admin")
                    {
                        return Json(new { success = false, message = "Không thể xóa tài khoản Admin!" });
                    }

                    using (var transaction = db.Database.BeginTransaction())
                    {
                        try
                        {
                            var histories = db.LoginHistories.Where(x => x.AccountID == user.AccountID);
                            if (histories.Any())
                            {
                                db.LoginHistories.RemoveRange(histories);
                            }

                            db.Accounts.Remove(user);
                            db.SaveChanges();

                            transaction.Commit();

                            FormsAuthentication.SignOut();
                            Session.Clear();
                            Session.Abandon();

                            Response.Cookies.Clear();
                            if (Request.Cookies[FormsAuthentication.FormsCookieName] != null)
                            {
                                var cookie = new HttpCookie(FormsAuthentication.FormsCookieName)
                                {
                                    Expires = DateTime.Now.AddDays(-1)
                                };
                                Response.Cookies.Add(cookie);
                            }

                            if (Request.Cookies["ASP.NET_SessionId"] != null)
                            {
                                var sessionCookie = new HttpCookie("ASP.NET_SessionId")
                                {
                                    Expires = DateTime.Now.AddDays(-1)
                                };
                                Response.Cookies.Add(sessionCookie);
                            }

                            return Json(new { success = true, message = "Tài khoản đã được xóa thành công" });
                        }
                        catch (Exception)
                        {
                            transaction.Rollback();
                            throw;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = "Lỗi khi xóa tài khoản: " + ex.Message });
            }
        }
            [HttpPost]
            [ValidateAntiForgeryToken]
            [Authorize(Roles = "Admin,User")]
            public JsonResult VerifyPassword(string password)
            {
                try
                {
                    if (!User.Identity.IsAuthenticated)
                    {
                        return Json(new { success = false, message = "Người dùng chưa đăng nhập" });
                    }

                    var currentUsername = User.Identity.Name;

                    using (var db = new QLThietBiEntities())
                    {
                        var user = db.Accounts.FirstOrDefault(a => a.Username == currentUsername);
                        if (user == null)
                        {
                            return Json(new { success = false, message = "Không tìm thấy tài khoản" });
                        }

                        bool isValid = (user.Password == password);

                        return Json(new
                        {
                            success = isValid,
                            message = isValid ? "Mật khẩu hợp lệ" : "Mật khẩu không chính xác"
                        });
                    }
                }
                catch (Exception ex)
                {
                    return Json(new { success = false, message = "Lỗi hệ thống: " + ex.Message });
                }
            }


        }
    
}