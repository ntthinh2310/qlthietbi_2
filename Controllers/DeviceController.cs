using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Data.Entity;
using qlthietbi_2.ViewModels;

using Newtonsoft.Json;
namespace qlthietbi_2.Controllers
{
    public class DeviceController : Controller
    {
        // GET: Device/Index
        public ActionResult Index(string searchString, string sortOrder, string deviceTypeFilter, string statusFilter)
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

                return View("Index", viewModel);
            }
        }


    }
}