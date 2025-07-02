using PagedList;
using qlthietbi_2.Models;
using qlthietbi_2.ViewModels;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Data.Entity.Infrastructure;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;
namespace qlthietbi_2.Controllers
{
    public class AdminController : Controller
    {
        [Authorize(Roles = "Admin")]
        public ActionResult Index()
        {
            return View();
        }
        [Authorize(Roles = "Admin")]
        public ActionResult ManagerDevices(string searchString, string sortOrder, string deviceTypeFilter, string statusFilter)
        {
            using (QLThietBiEntities db = new QLThietBiEntities())
            {
                ViewBag.CurrentFilter = searchString;
                ViewBag.CurrentSort = sortOrder;
                ViewBag.DeviceIDSortParam = String.IsNullOrEmpty(sortOrder) ? "id_desc" : "";
                ViewBag.DeviceNameSortParam = sortOrder == "DeviceName" ? "devicename_desc" : "DeviceName";
                ViewBag.DeviceTypeSortParam = sortOrder == "DeviceType" ? "devicetype_desc" : "DeviceType";
                ViewBag.StatusSortParam = sortOrder == "Status" ? "status_desc" : "Status";

                ViewBag.DeviceIDSortParam = String.IsNullOrEmpty(sortOrder) ? "id_desc" : "";

                var devices = db.Devices.Include(d => d.DeviceType).AsQueryable();

                if (!string.IsNullOrEmpty(searchString))
                {
                    devices = devices.Where(d => d.DeviceName.Contains(searchString));
                }
                if (!String.IsNullOrEmpty(deviceTypeFilter))
                {
                    devices = devices.Where(d => d.DeviceType.TypeName == deviceTypeFilter);
                }

                // Lọc theo Status
                if (!String.IsNullOrEmpty(statusFilter))
                {
                    devices = devices.Where(d => d.Status == statusFilter);
                }
                ViewBag.DeviceTypeFilter = new SelectList(db.DeviceTypes.Select(t => t.TypeName).Distinct().ToList());
                var allTypes = db.DeviceTypes.Select(t => t.TypeName).Distinct().ToList();
                ViewBag.DeviceTypeFilter = allTypes;
                ViewBag.StatusFilter = new List<string> { "Hoạt động", "Bảo trì" };
                ViewBag.CurrentDeviceType = deviceTypeFilter;
                ViewBag.CurrentStatus = statusFilter;
                switch (sortOrder)
                {
                    case "id_desc":
                        devices = devices.OrderByDescending(d => d.DeviceID);
                        break;
                    case "DeviceName":
                        devices = devices.OrderBy(d => d.DeviceName);
                        break;
                    case "devicename_desc":
                        devices = devices.OrderByDescending(d => d.DeviceName);
                        break;
                    case "DeviceType":
                        devices = devices.OrderBy(d => d.DeviceType.TypeName);
                        break;
                    case "devicetype_desc":
                        devices = devices.OrderByDescending(d => d.DeviceType.TypeName);
                        break;
                    case "Status":
                        devices = devices.OrderBy(d => d.Status);
                        break;
                    case "status_desc":
                        devices = devices.OrderByDescending(d => d.Status);
                        break;
                    default:
                        devices = devices.OrderBy(d => d.DeviceID);
                        break;
                }

                var viewModel = devices.Select(d => new DeviceViewModel
                {
                    DeviceID = d.DeviceID,
                    DeviceName = d.DeviceName,
                    Manufacturer = d.Manufacturer,
                    Model = d.Model,
                    PurchaseDate = d.PurchaseDate,
                    WarrantyUntil = d.WarrantyUntil,
                    Status = d.Status,
                    Notes = d.Notes,
                    TypeName = d.DeviceType.TypeName
                }).ToList();


                ViewBag.CurrentDeviceType = deviceTypeFilter ?? "";
                ViewBag.CurrentStatus = statusFilter ?? "";

                return View("ManagerDevices", viewModel);
            }
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin")]
        public ActionResult Edit(
        int DeviceID,
        string DeviceName,
        string Manufacturer,
        string Model,
        DateTime? PurchaseDate,
        DateTime? WarrantyUntil,
        string Status,
        string Notes,
        string TypeName)
        {
            try
            {
                using (var db = new QLThietBiEntities())
                {
                    var device = db.Devices.Find(DeviceID);
                    if (device == null)
                    {
                        TempData["ErrorMessage"] = "Thiết bị không tồn tại";
                        return RedirectToAction("ManagerDevices");
                    }

                    device.DeviceName = DeviceName;
                    device.Manufacturer = Manufacturer;
                    device.Model = Model;
                    device.PurchaseDate = PurchaseDate;
                    device.WarrantyUntil = WarrantyUntil;
                    device.Status = Status;
                    device.Notes = Notes;

                    var deviceType = db.DeviceTypes.FirstOrDefault(t => t.TypeName == TypeName);
                    if (deviceType != null)
                    {
                        device.TypeID = deviceType.TypeID;
                    }

                    db.SaveChanges();
                    if (FormsAuthentication.FormsCookieName != null)
                    {
                        var authCookie = Request.Cookies[FormsAuthentication.FormsCookieName];
                        if (authCookie != null)
                        {
                            var ticket = FormsAuthentication.Decrypt(authCookie.Value);
                            if (ticket != null && !ticket.Expired)
                            {
                                var newTicket = FormsAuthentication.RenewTicketIfOld(ticket);
                                var encTicket = FormsAuthentication.Encrypt(newTicket);
                                authCookie.Value = encTicket;
                                Response.Cookies.Set(authCookie);
                            }
                        }
                    }
                    TempData["SuccessMessage"] = "Cập nhật thiết bị thành công";
                    return RedirectToAction("ManagerDevices");
                }
            }
            catch (Exception ex)
            {
                TempData["ErrorMessage"] = "Lỗi hệ thống: " + ex.Message;
                return RedirectToAction("ManagerDevices");
            }
        }
        [HttpPost]
        [ValidateAntiForgeryToken]

        public ActionResult Delete(int id)
        {
            try
            {
                using (var db = new QLThietBiEntities())
                {
                    var device = db.Devices.Find(id);
                    if (device == null)
                    {
                        return Json(new { success = false, message = "Thiết bị không tồn tại" });
                    }

                    db.Devices.Remove(device);
                    db.SaveChanges();

                    return Json(new { success = true, message = "Xóa thành công" });
                }
            }
            catch (Exception ex)
            {
                return Json(new
                {
                    success = false,
                    message = "Không thể xóa: " + ex.Message
                });
            }
        }
        [Authorize(Roles = "Admin")]
        public ActionResult ManagerDeviceTypes()
        {
            using (QLThietBiEntities db = new QLThietBiEntities())
            {
                var deviceTypes = db.DeviceTypes.ToList();
                return View(deviceTypes);
            }
        }
        public ActionResult Edit_DeviceTypes(
        int TypeID,
        string TypeName,
        string Description
        )
        {
            try
            {
                using (var db = new QLThietBiEntities())
                {
                    var device = db.DeviceTypes.Find(TypeID);
                    if (device == null)
                    {
                        TempData["ErrorMessage"] = "Loại thiết bị không tồn tại";
                        return RedirectToAction("ManagerDeviceTypes");
                    }
                    device.TypeName = TypeName;
                    device.Description = Description;

                    db.SaveChanges();

                    TempData["SuccessMessage"] = "Cập nhật loại thiết bị thành công";
                    return RedirectToAction("ManagerDeviceTypes");
                }
            }
            catch (Exception ex)
            {
                TempData["ErrorMessage"] = "Lỗi hệ thống: " + ex.Message;
                return RedirectToAction("ManagerDeviceTypes");
            }
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult DeleteDeviceType(int typeID)
        {
            using (QLThietBiEntities db = new QLThietBiEntities())
            {
                var hasDevices = db.Devices.Any(d => d.TypeID == typeID);

                if (hasDevices)
                {
                    return Json(new { success = false, message = "Không thể xóa vì có thiết bị đang sử dụng loại này!" });
                }

                // Nếu không có ràng buộc thì xóa
                var deviceType = db.DeviceTypes.Find(typeID);
                db.DeviceTypes.Remove(deviceType);
                db.SaveChanges();

                return Json(new { success = true, message = "Xóa thành công!" });
            }

        }
        [HttpPost]
        [ValidateAntiForgeryToken]

        public ActionResult AddDeviceType(string typeName, string description)
        {
            using (QLThietBiEntities db = new QLThietBiEntities())
            {
                try
                {
                    if (string.IsNullOrWhiteSpace(typeName))
                    {
                        return Json(new { success = false, message = "Tên loại thiết bị không được để trống!" });
                    }

                    if (db.DeviceTypes.Any(t => t.TypeName == typeName))
                    {
                        return Json(new { success = false, message = "Tên loại thiết bị đã tồn tại!" });
                    }

                    var newDeviceType = new DeviceType
                    {
                        TypeName = typeName.Trim(),
                        Description = description?.Trim()
                    };

                    db.DeviceTypes.Add(newDeviceType);
                    db.SaveChanges();

                    return Json(new
                    {
                        success = true,
                        message = "Thêm loại thiết bị thành công!",
                    });
                }
                catch (Exception ex)
                {
                    return Json(new { success = false, message = "Lỗi: " + ex.Message });
                }
            }
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult AddDevice(string NewDeviceName, string NewTypeName, string NewStatus, string NewManufacturer, string NewModel, DateTime? NewPurchaseDate, DateTime? NewWarrantyUntil, string NewNotes)
        {
            using (QLThietBiEntities db = new QLThietBiEntities())
            {
                try
                {
                    var type = db.DeviceTypes.FirstOrDefault(t => t.TypeName == NewTypeName);
                    if (type == null)
                    {
                        return Json(new { success = false, message = "Loại thiết bị không tồn tại trong hệ thống!" });
                    }

                    var newDevice = new Device
                    {
                        DeviceName = NewDeviceName,
                        TypeID = type.TypeID,
                        Status = NewStatus,
                        Manufacturer = NewManufacturer,
                        Model = NewModel,
                        PurchaseDate = NewPurchaseDate,
                        WarrantyUntil = NewWarrantyUntil,
                        Notes = NewNotes
                    };

                    db.Devices.Add(newDevice);
                    db.SaveChanges();

                    return Json(new
                    {
                        success = true,
                        message = "Thêm thiết bị thành công!",
                    });

                }
                catch (Exception ex)
                {
                    return Json(new { success = false, message = "Lỗi: " + ex.Message });
                }
            }
        }
        [Authorize(Roles = "Admin")]
        public ActionResult ManagerAccount()
        {
            using (QLThietBiEntities db = new QLThietBiEntities())
            {
                var Accounts = db.Accounts.ToList();
                return View(Accounts);
            }

        }
        public ActionResult DeleteAccount(int AccountID)
        {
            using (QLThietBiEntities db = new QLThietBiEntities())
            {
                var account = db.Accounts.Find(AccountID);
                if (account == null)
                {
                    return Json(new { success = false, message = "Tài khoản không tồn tại" });
                }
                db.Accounts.Remove(account);
                db.SaveChanges();
                return Json(new { success = true, message = "Xóa tài khoản thành công" });
            }
        }

        [Authorize(Roles = "Admin")]
        public ActionResult ManagerLoginHistory(string searchString, string sortOrder, int? page)
        {
            ViewBag.CurrentSort = sortOrder;
            ViewBag.NameSortParm = String.IsNullOrEmpty(sortOrder) ? "name_desc" : "";
            ViewBag.DateSortParm = sortOrder == "Date" ? "date_desc" : "Date";
            ViewBag.DurationSortParm = sortOrder == "Duration" ? "duration_desc" : "Duration";
            ViewBag.CurrentFilter = searchString;

            using (var db = new QLThietBiEntities())
            {
                // Base query
                var query = from l in db.LoginHistories
                            join a in db.Accounts on l.AccountID equals a.AccountID
                            select new LoginHistoryViewModel
                            {
                                AccountID = l.AccountID,
                                Username = a.Username,
                                LoginTime = l.LoginTime,
                                LogoutTime = l.LogoutTime,
                                IPAddress = l.IPAddress,
                                DurationMinutes = l.LogoutTime != null ?
                                    (int?)DbFunctions.DiffMinutes(l.LoginTime, l.LogoutTime).Value :
                                    (int?)DbFunctions.DiffMinutes(l.LoginTime, DateTime.Now).Value,
                                Status = l.LogoutTime.HasValue ? "Đã đăng xuất" : "Đang hoạt động"
                            };

                // Search
                if (!String.IsNullOrEmpty(searchString))
                {
                    query = query.Where(x => x.Username.Contains(searchString));
                }

                // Sorting
                switch (sortOrder)
                {
                    case "name_desc":
                        query = query.OrderByDescending(x => x.Username);
                        break;
                    case "Date":
                        query = query.OrderBy(x => x.LoginTime);
                        break;
                    case "date_desc":
                        query = query.OrderByDescending(x => x.LoginTime);
                        break;
                    case "Duration":
                        query = query.OrderBy(x => x.DurationMinutes ?? int.MaxValue);
                        break;
                    case "duration_desc":
                        query = query.OrderByDescending(x => x.DurationMinutes ?? int.MinValue);
                        break;
                    default:
                        query = query.OrderByDescending(x => x.LoginTime);
                        break;
                }

                // Paging
                int pageSize = 15;
                int pageNumber = (page ?? 1);
                return View(query.ToPagedList(pageNumber, pageSize));
            }
        }
        public ActionResult KeepAlive()
        {
            return Content("OK");
        }

        [HttpPost]
        public ActionResult TrackLogout()
        {
            if (User.Identity.IsAuthenticated)
            {
                var userId = int.Parse(((FormsIdentity)User.Identity).Ticket.UserData);

                using (QLThietBiEntities db = new QLThietBiEntities())
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

    }
}