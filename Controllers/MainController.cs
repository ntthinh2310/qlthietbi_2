using qlthietbi_2.ViewModels;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace qlthietbi_2.Controllers
{
    public class MainController : Controller
    {
        private QLThietBiEntities db = new QLThietBiEntities();

        // GET: Main
        [Authorize(Roles = "Admin,User")]
        public ActionResult Index()
        {
            // Get basic statistics
            var totalDevices = db.Devices.Count();
            var totalDeviceTypes = db.DeviceTypes.Count();
            var activeDevices = db.Devices.Count(d => d.Status == "Active");
            var maintenanceDevices = db.Devices.Count(d => d.Status == "Maintenance");
            var activeDevicePercentage = totalDevices > 0 ? (activeDevices * 100 / totalDevices) : 0;

            // Get data for bar chart
            var deviceCountsByType = db.Devices
                .GroupBy(d => d.TypeID)
                .Select(g => new {
                    TypeID = g.Key,
                    Count = g.Count()
                })
                .ToList();

            var typeNames = db.DeviceTypes.ToDictionary(t => t.TypeID, t => t.TypeName);

            // Prepare data for pie chart
            var deviceDistribution = new List<DeviceDistributionItem>();
            var colors = new string[] { "#4e73df", "#1cc88a", "#36b9cc", "#f6c23e", "#e74a3b", "#858796", "#f8f9fc" };
            var hoverColors = new string[] { "#2e59d9", "#17a673", "#2c9faf", "#dda20a", "#be2617", "#60616f", "#dde2f1" };

            int colorIndex = 0;
            foreach (var item in deviceCountsByType)
            {
                var typeName = typeNames.ContainsKey(item.TypeID) ? typeNames[item.TypeID] : "Unknown";
                deviceDistribution.Add(new DeviceDistributionItem
                {
                    TypeName = typeName,
                    Count = item.Count,
                    Color = colors[colorIndex % colors.Length],
                    HoverColor = hoverColors[colorIndex % hoverColors.Length]
                });
                colorIndex++;
            }

            // Create view model
            var viewModel = new DashboardViewModel
            {
                TotalDevices = totalDevices,
                TotalDeviceTypes = totalDeviceTypes,
                ActiveDevices = activeDevices,
                MaintenanceDevices = maintenanceDevices,
                ActiveDevicePercentage = activeDevicePercentage,
                TypeNames = deviceCountsByType.Select(x =>
                    typeNames.ContainsKey(x.TypeID) ? typeNames[x.TypeID] : "Unknown").ToList(),
                DeviceCounts = deviceCountsByType.Select(x => x.Count).ToList(),
                DeviceDistribution = deviceDistribution
            };

            return View(viewModel);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                db.Dispose();
            }
            base.Dispose(disposing);
        }
        [Authorize(Roles = "Admin,User")]
        public ActionResult About()
        {
            return View();
        }
    }
}