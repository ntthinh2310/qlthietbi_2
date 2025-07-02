using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;


namespace qlthietbi_2.Controllers
{
    public class DeviceTypesController : Controller
    {
        // GET: DeviceTypes
        public ActionResult Index()
        {
            using (QLThietBiEntities db = new QLThietBiEntities())
            {
                var deviceTypes = db.DeviceTypes.ToList();
                return View(deviceTypes);
            }
        }   
    }
}