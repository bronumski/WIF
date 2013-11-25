﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace RelyingParty.Controllers
{
    [Authorize]
    public class AuthorizedController : Controller
    {
        //
        // GET: /Authorized/

        public ActionResult Index()
        {
            return View();
        }

    }
}
