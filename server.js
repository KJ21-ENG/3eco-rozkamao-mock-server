/**
 * Roz Kamao Mock Server
 * 
 * Custom json-server instance with middleware for:
 * - Lead lifecycle management (OTP → Register → FOS Selection → Booking)
 * - FOS availability auto-update on bookings
 * - CORS enabled for cross-device access
 * 
 * Run: node server.js
 * Access: http://0.0.0.0:4000
 */

const jsonServer = require("json-server");
const moment = require("moment");

const server = jsonServer.create();
const router = jsonServer.router("db.json");
const middlewares = jsonServer.defaults({ noCors: false });
const initialDbState = JSON.parse(JSON.stringify(router.db.getState()));
const PREVIEW_API_TOKEN = process.env.PREVIEW_API_TOKEN || "";
const PREVIEW_ADMIN_TOKEN = process.env.PREVIEW_ADMIN_TOKEN || "";
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

const isOriginAllowed = (origin) =>
  ALLOWED_ORIGINS.length === 0 || ALLOWED_ORIGINS.includes(origin);

const resetDemoState = () => {
  if (typeof router.db.setState === "function") {
    router.db.setState(JSON.parse(JSON.stringify(initialDbState))).write();
    return;
  }
  Object.keys(initialDbState).forEach((key) => {
    router.db.set(key, JSON.parse(JSON.stringify(initialDbState[key]))).write();
  });
};

// CORS policy, configurable by ALLOWED_ORIGINS.
server.use((req, res, next) => {
  const requestOrigin = req.headers.origin;
  if (requestOrigin && isOriginAllowed(requestOrigin)) {
    res.header("Access-Control-Allow-Origin", requestOrigin);
  } else if (!requestOrigin && ALLOWED_ORIGINS.length > 0) {
    res.header("Access-Control-Allow-Origin", ALLOWED_ORIGINS[0]);
  } else if (ALLOWED_ORIGINS.length === 0) {
    res.header("Access-Control-Allow-Origin", "*");
  }
  res.header("Vary", "Origin");
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS");
  res.header(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, x-preview-token, x-admin-token"
  );
  if (req.method === "OPTIONS") {
    return res.sendStatus(200);
  }
  if (requestOrigin && !isOriginAllowed(requestOrigin)) {
    return res.status(403).json({
      status: "FAIL",
      message: "Origin not allowed.",
    });
  }
  next();
});

server.use(middlewares);
// Increase body limit to 10MB for base64 image uploads
const express = require("express");
server.use(express.json({ limit: "10mb" }));
server.use(express.urlencoded({ limit: "10mb", extended: true }));

server.get("/health", (_, res) => {
  res.json({ status: "SUCCESS", message: "OK" });
});

// Require preview token for all app-facing API/data routes.
server.use((req, res, next) => {
  if (req.path === "/api/admin/reset-demo") {
    return next();
  }
  const protectedPrefixes = ["/api/", "/leads", "/fos", "/fosAvailability"];
  const isProtectedRoute = protectedPrefixes.some((prefix) => req.path.startsWith(prefix));
  if (!isProtectedRoute) {
    return next();
  }
  if (!PREVIEW_API_TOKEN) {
    return next();
  }
  const providedToken = req.header("x-preview-token");
  if (providedToken !== PREVIEW_API_TOKEN) {
    return res.status(401).json({
      status: "FAIL",
      message: "Unauthorized. Missing or invalid preview token.",
    });
  }
  next();
});

// Demo reset endpoint (admin token required).
server.post("/api/admin/reset-demo", (req, res) => {
  if (!PREVIEW_ADMIN_TOKEN) {
    return res.status(500).json({
      status: "FAIL",
      message: "Admin reset is not configured.",
    });
  }
  const providedAdminToken = req.header("x-admin-token");
  if (providedAdminToken !== PREVIEW_ADMIN_TOKEN) {
    return res.status(401).json({
      status: "FAIL",
      message: "Unauthorized. Invalid admin token.",
    });
  }

  resetDemoState();
  return res.json({
    status: "SUCCESS",
    message: "Demo data reset to seed state.",
  });
});

// ============================================================
// Custom Routes (before json-server default router)
// ============================================================

/**
 * POST /api/lead/login-context
 * Resolve whether login should continue old SPro OTP flow or route to Roz pages.
 */
server.post("/api/lead/login-context", (req, res) => {
  const { mobile } = req.body || {};
  if (!mobile || !/^\d{10}$/.test(mobile)) {
    return res.status(400).json({
      status: "FAIL",
      message: "Please enter a valid 10-digit mobile number.",
    });
  }

  const db = router.db;
  const leads = db
    .get("leads")
    .filter({ mobile, isDeleted: false })
    .value();

  const ACTIVE_STATUSES = new Set([
    "LEAD_CREATED",
    "REGISTERED",
    "FOS_SELECTED",
    "APPOINTMENT_BOOKED",
    "VISITED_FOS",
  ]);
  // Only stages that should force a fresh Roz registration.
  const REGISTRATION_REQUIRED_STATUSES = new Set(["DROPPED"]);

  const byUpdatedAtDesc = (a, b) => {
    const aTs = new Date(a?.updatedAt || a?.createdAt || 0).getTime();
    const bTs = new Date(b?.updatedAt || b?.createdAt || 0).getTime();
    return bTs - aTs;
  };

  const activeLead = leads
    .filter((lead) => ACTIVE_STATUSES.has(lead.status))
    .sort(byUpdatedAtDesc)[0];
  if (activeLead) {
    return res.json({
      status: "SUCCESS",
      flowType: "ROZ_ACTIVE",
      leadId: activeLead.id,
      message: "Active Roz lead found. Opening My Booking.",
    });
  }

  const inactiveLead = leads
    .filter((lead) => REGISTRATION_REQUIRED_STATUSES.has(lead.status))
    .sort(byUpdatedAtDesc)[0];
  if (inactiveLead) {
    return res.json({
      status: "SUCCESS",
      flowType: "ROZ_INACTIVE",
      leadId: inactiveLead.id,
      message: "Roz lead found but inactive. Please register first.",
    });
  }

  return res.json({
    status: "SUCCESS",
    flowType: "NOT_FOUND",
    message: "No relevant Roz lead found. Continue SPro login flow.",
  });
});

/**
 * POST /api/lead/send-otp
 * Simulates OTP sending — always succeeds with code 1234
 */
server.post("/api/lead/send-otp", (req, res) => {
  const { mobile } = req.body;
  if (!mobile || !/^\d{10}$/.test(mobile)) {
    return res.status(400).json({
      status: "FAIL",
      message: "Please enter a valid 10-digit mobile number.",
    });
  }

  const db = router.db; // lowdb instance
  const existingLead = db.get("leads").find({ mobile, isDeleted: false }).value();

  if (existingLead) {
    // Update OTP on existing lead
    db.get("leads")
      .find({ id: existingLead.id })
      .assign({ otp: "1234", updatedAt: moment().toISOString() })
      .write();
  } else {
    // Create new lead
    const newLead = {
      id: "lead_" + Date.now(),
      mobile: mobile,
      name: "",
      city: "",
      status: "LEAD_CREATED",
      source: req.body.source || "direct",
      selectedFosId: null,
      selectedFosName: null,
      appointmentDate: null,
      otp: "1234",
      statusHistory: [
        {
          status: "LEAD_CREATED",
          timestamp: moment().toISOString(),
          note: "Lead created via OTP request",
        },
      ],
      isDeleted: false,
      createdAt: moment().toISOString(),
      updatedAt: moment().toISOString(),
    };
    db.get("leads").push(newLead).write();
  }

  return res.json({
    status: "SUCCESS",
    message: "OTP sent successfully! (Demo: use 1234)",
    data: { otp: "1234" },
  });
});

/**
 * POST /api/lead/verify-otp
 * Validates OTP (accepts 1234) and returns lead data + token
 */
server.post("/api/lead/verify-otp", (req, res) => {
  const { mobile, otp } = req.body;
  if (!mobile || !otp) {
    return res.status(400).json({
      status: "FAIL",
      message: "Mobile and OTP are required.",
    });
  }

  const db = router.db;
  const lead = db.get("leads").find({ mobile, isDeleted: false }).value();

  if (!lead) {
    return res.status(404).json({
      status: "FAIL",
      message: "No registration found. Please request OTP first.",
    });
  }

  // Accept 1234 as master OTP
  if (otp !== "1234" && otp !== lead.otp) {
    return res.status(400).json({
      status: "FAIL",
      message: "Entered code is not matching. Try again.",
    });
  }

  // Clear OTP
  db.get("leads")
    .find({ id: lead.id })
    .assign({ otp: null, updatedAt: moment().toISOString() })
    .write();

  return res.json({
    status: "SUCCESS",
    message: "OTP verified!",
    data: {
      token: "JWT preview-token-" + lead.id,
      lead: {
        id: lead.id,
        mobile: lead.mobile,
        name: lead.name,
        status: lead.status,
      },
    },
  });
});

/**
 * POST /api/lead/register
 * Submit driver details: basic info + documents + photo
 */
server.post("/api/lead/register", (req, res) => {
  const {
    mobile, name, city,
    recruiterName, aadharNumber, panNumber, dlType,
    bankAccount, bankIfsc,
    aadharImage, panImage, dlImage, bankPassbookImage, driverPhoto,
  } = req.body;

  if (!mobile || !name || !city) {
    return res.status(400).json({
      status: "FAIL",
      message: "Mobile, name, and city are required.",
    });
  }

  const db = router.db;
  const lead = db.get("leads").find({ mobile, isDeleted: false }).value();

  if (!lead) {
    return res.status(404).json({
      status: "FAIL",
      message: "Lead not found. Please start registration again.",
    });
  }

  const updatedHistory = [
    ...(lead.statusHistory || []),
    {
      status: "REGISTERED",
      timestamp: moment().toISOString(),
      note: "Basic details submitted",
    },
  ];

  // Build update object — always set name/city/status,
  // only set optional fields if provided
  const updates = {
    name: name.trim(),
    city: city.trim(),
    status: "REGISTERED",
    statusHistory: updatedHistory,
    updatedAt: moment().toISOString(),
  };

  if (recruiterName) updates.recruiterName = recruiterName.trim();
  if (aadharNumber)  updates.aadharNumber = aadharNumber.trim();
  if (panNumber)     updates.panNumber = panNumber.trim();
  if (dlType)        updates.dlType = dlType;
  if (bankAccount)   updates.bankAccount = bankAccount.trim();
  if (bankIfsc)      updates.bankIfsc = bankIfsc.trim();

  // Store base64 image flags (store a truncated marker to keep db.json small)
  // In production these would be uploaded to S3/GCS, here we just note presence.
  if (driverPhoto)      updates.driverPhoto = driverPhoto.substring(0, 80) + "...";
  if (aadharImage)      updates.aadharImage = aadharImage.substring(0, 80) + "...";
  if (panImage)         updates.panImage = panImage.substring(0, 80) + "...";
  if (dlImage)          updates.dlImage = dlImage.substring(0, 80) + "...";
  if (bankPassbookImage) updates.bankPassbookImage = bankPassbookImage.substring(0, 80) + "...";

  // Count how many documents were uploaded
  const docCount = [driverPhoto, aadharImage, panImage, dlImage, bankPassbookImage]
    .filter(Boolean).length;
  updates.documentsUploaded = docCount;

  db.get("leads")
    .find({ id: lead.id })
    .assign(updates)
    .write();

  const updatedLead = db.get("leads").find({ id: lead.id }).value();

  return res.json({
    status: "SUCCESS",
    message: "Registration successful!",
    data: { lead: updatedLead },
  });
});

/**
 * POST /api/lead/select-fos
 * Select a FOS
 */
server.post("/api/lead/select-fos", (req, res) => {
  const { leadId, fosId } = req.body;
  if (!leadId || !fosId) {
    return res.status(400).json({
      status: "FAIL",
      message: "Lead ID and FOS ID are required.",
    });
  }

  const db = router.db;
  const lead = db.get("leads").find({ id: leadId, isDeleted: false }).value();
  const fos = db.get("fos").find({ id: fosId }).value();

  if (!lead) {
    return res.status(404).json({ status: "FAIL", message: "Lead not found." });
  }
  if (!fos) {
    return res.status(404).json({ status: "FAIL", message: "FOS not found." });
  }
  if (fos.isAvailable === false) {
    return res.status(400).json({
      status: "FAIL",
      message: "Selected FOS is currently unavailable.",
    });
  }

  const updatedHistory = [
    ...(lead.statusHistory || []),
    {
      status: "FOS_SELECTED",
      timestamp: moment().toISOString(),
      note: `Selected FOS: ${fos.name} (${fos.code})`,
    },
  ];

  db.get("leads")
    .find({ id: lead.id })
    .assign({
      selectedFosId: fosId,
      selectedFosName: fos.name,
      selectedFosCode: fos.code,
      selectedFosAddress: fos.addresses,
      selectedFosLatitude: fos.latitude,
      selectedFosLongitude: fos.longitude,
      status: "FOS_SELECTED",
      statusHistory: updatedHistory,
      updatedAt: moment().toISOString(),
    })
    .write();

  return res.json({
    status: "SUCCESS",
    message: "FOS selected successfully.",
    data: { fosName: fos.name, fosCode: fos.code },
  });
});

/**
 * POST /api/lead/book-appointment
 * Book an appointment date
 */
server.post("/api/lead/book-appointment", (req, res) => {
  const { leadId, date } = req.body;
  if (!leadId || !date) {
    return res.status(400).json({
      status: "FAIL",
      message: "Lead ID and date are required.",
    });
  }

  const db = router.db;
  const lead = db.get("leads").find({ id: leadId, isDeleted: false }).value();

  if (!lead) {
    return res.status(404).json({ status: "FAIL", message: "Lead not found." });
  }
  if (!lead.selectedFosId) {
    return res.status(400).json({
      status: "FAIL",
      message: "Please select a FOS first.",
    });
  }
  const selectedFos = db.get("fos").find({ id: lead.selectedFosId }).value();
  if (selectedFos && selectedFos.isAvailable === false) {
    return res.status(400).json({
      status: "FAIL",
      message: "Selected FOS is currently unavailable for bookings.",
    });
  }

  // Check availability
  const availability = db
    .get("fosAvailability")
    .find({ fosId: lead.selectedFosId, date: date })
    .value();

  if (availability) {
    if (availability.isBlocked) {
      return res.status(400).json({
        status: "FAIL",
        message: "This date is blocked.",
      });
    }
    if (availability.currentBookings >= availability.maxCapacity) {
      return res.status(400).json({
        status: "FAIL",
        message: "No slots available on this date.",
      });
    }
    // Increment booking count
    db.get("fosAvailability")
      .find({ id: availability.id })
      .assign({ currentBookings: availability.currentBookings + 1 })
      .write();
  } else {
    // Create availability record
    db.get("fosAvailability")
      .push({
        id: "fa_" + Date.now(),
        fosId: lead.selectedFosId,
        date: date,
        maxCapacity: 10,
        currentBookings: 1,
        isBlocked: false,
      })
      .write();
  }

  const fos = db.get("fos").find({ id: lead.selectedFosId }).value();
  const updatedHistory = [
    ...(lead.statusHistory || []),
    {
      status: "APPOINTMENT_BOOKED",
      timestamp: moment().toISOString(),
      note: `Appointment booked for ${date} at ${fos?.name || "FOS"}`,
    },
  ];

  db.get("leads")
    .find({ id: lead.id })
    .assign({
      appointmentDate: date,
      status: "APPOINTMENT_BOOKED",
      statusHistory: updatedHistory,
      updatedAt: moment().toISOString(),
    })
    .write();

  return res.json({
    status: "SUCCESS",
    message: "Appointment booked successfully!",
    data: {
      date: date,
      fosName: fos?.name,
      fosCode: fos?.code,
      addresses: fos?.addresses,
      latitude: fos?.latitude,
      longitude: fos?.longitude,
    },
  });
});

/**
 * POST /api/lead/cancel-booking
 */
server.post("/api/lead/cancel-booking", (req, res) => {
  const { leadId } = req.body;
  const db = router.db;
  const lead = db.get("leads").find({ id: leadId, isDeleted: false }).value();

  if (!lead || lead.status !== "APPOINTMENT_BOOKED") {
    return res.status(400).json({
      status: "FAIL",
      message: "No active booking to cancel.",
    });
  }

  // Decrement availability
  if (lead.appointmentDate && lead.selectedFosId) {
    const avail = db
      .get("fosAvailability")
      .find({ fosId: lead.selectedFosId, date: lead.appointmentDate })
      .value();
    if (avail && avail.currentBookings > 0) {
      db.get("fosAvailability")
        .find({ id: avail.id })
        .assign({ currentBookings: avail.currentBookings - 1 })
        .write();
    }
  }

  const updatedHistory = [
    ...(lead.statusHistory || []),
    {
      status: "FOS_SELECTED",
      timestamp: moment().toISOString(),
      note: `Booking cancelled (was ${lead.appointmentDate})`,
    },
  ];

  db.get("leads")
    .find({ id: lead.id })
    .assign({
      appointmentDate: null,
      status: "FOS_SELECTED",
      statusHistory: updatedHistory,
      updatedAt: moment().toISOString(),
    })
    .write();

  return res.json({
    status: "SUCCESS",
    message: "Booking cancelled.",
  });
});

/**
 * POST /api/lead/reschedule
 */
server.post("/api/lead/reschedule", (req, res) => {
  const { leadId, newDate } = req.body;
  const db = router.db;
  const lead = db.get("leads").find({ id: leadId, isDeleted: false }).value();

  if (!lead || lead.status !== "APPOINTMENT_BOOKED") {
    return res.status(400).json({
      status: "FAIL",
      message: "No active booking to reschedule.",
    });
  }

  // Decrement old date
  if (lead.appointmentDate && lead.selectedFosId) {
    const oldAvail = db
      .get("fosAvailability")
      .find({ fosId: lead.selectedFosId, date: lead.appointmentDate })
      .value();
    if (oldAvail && oldAvail.currentBookings > 0) {
      db.get("fosAvailability")
        .find({ id: oldAvail.id })
        .assign({ currentBookings: oldAvail.currentBookings - 1 })
        .write();
    }
  }

  // Increment new date
  const newAvail = db
    .get("fosAvailability")
    .find({ fosId: lead.selectedFosId, date: newDate })
    .value();
  if (newAvail) {
    db.get("fosAvailability")
      .find({ id: newAvail.id })
      .assign({ currentBookings: newAvail.currentBookings + 1 })
      .write();
  } else {
    db.get("fosAvailability")
      .push({
        id: "fa_" + Date.now(),
        fosId: lead.selectedFosId,
        date: newDate,
        maxCapacity: 10,
        currentBookings: 1,
        isBlocked: false,
      })
      .write();
  }

  const oldDate = lead.appointmentDate;
  const updatedHistory = [
    ...(lead.statusHistory || []),
    {
      status: "APPOINTMENT_BOOKED",
      timestamp: moment().toISOString(),
      note: `Rescheduled from ${oldDate} to ${newDate}`,
    },
  ];

  db.get("leads")
    .find({ id: lead.id })
    .assign({
      appointmentDate: newDate,
      statusHistory: updatedHistory,
      updatedAt: moment().toISOString(),
    })
    .write();

  return res.json({
    status: "SUCCESS",
    message: "Rescheduled successfully!",
    data: { oldDate, newDate },
  });
});

/**
 * POST /api/lead/mark-visited
 * Admin marks lead as visited
 */
server.post("/api/lead/mark-visited", (req, res) => {
  const { leadId } = req.body;
  const db = router.db;
  const lead = db.get("leads").find({ id: leadId, isDeleted: false }).value();

  if (!lead) {
    return res.status(404).json({ status: "FAIL", message: "Lead not found." });
  }

  const updatedHistory = [
    ...(lead.statusHistory || []),
    {
      status: "VISITED_FOS",
      timestamp: moment().toISOString(),
      note: "Driver visited FOS — marked by admin",
    },
  ];

  db.get("leads")
    .find({ id: lead.id })
    .assign({
      status: "VISITED_FOS",
      statusHistory: updatedHistory,
      updatedAt: moment().toISOString(),
    })
    .write();

  return res.json({
    status: "SUCCESS",
    message: "Marked as visited.",
  });
});

/**
 * POST /api/lead/convert-to-spro
 * Admin converts lead to SPro
 */
server.post("/api/lead/convert-to-spro", (req, res) => {
  const { leadId } = req.body;
  const db = router.db;
  const lead = db.get("leads").find({ id: leadId, isDeleted: false }).value();

  if (!lead) {
    return res.status(404).json({ status: "FAIL", message: "Lead not found." });
  }

  const updatedHistory = [
    ...(lead.statusHistory || []),
    {
      status: "CONVERTED_TO_SPRO",
      timestamp: moment().toISOString(),
      note: "Lead converted to SPro — onboarding complete",
    },
  ];

  db.get("leads")
    .find({ id: lead.id })
    .assign({
      status: "CONVERTED_TO_SPRO",
      statusHistory: updatedHistory,
      updatedAt: moment().toISOString(),
    })
    .write();

  return res.json({
    status: "SUCCESS",
    message: "Lead converted to SPro!",
  });
});

/**
 * POST /api/lead/drop
 * Admin drops lead
 */
server.post("/api/lead/drop", (req, res) => {
  const { leadId, reason } = req.body;
  const db = router.db;
  const lead = db.get("leads").find({ id: leadId, isDeleted: false }).value();

  if (!lead) {
    return res.status(404).json({ status: "FAIL", message: "Lead not found." });
  }

  const updatedHistory = [
    ...(lead.statusHistory || []),
    {
      status: "DROPPED",
      timestamp: moment().toISOString(),
      note: reason || "Lead dropped by admin",
    },
  ];

  db.get("leads")
    .find({ id: lead.id })
    .assign({
      status: "DROPPED",
      dropOffStage: lead.status,
      statusHistory: updatedHistory,
      updatedAt: moment().toISOString(),
    })
    .write();

  return res.json({
    status: "SUCCESS",
    message: "Lead dropped.",
  });
});

/**
 * GET /api/lead/stats
 * Return funnel stats for dashboard
 */
server.get("/api/lead/stats", (req, res) => {
  const db = router.db;
  const leads = db.get("leads").filter({ isDeleted: false }).value();

  const stats = {
    total: leads.length,
    LEAD_CREATED: leads.filter((l) => l.status === "LEAD_CREATED").length,
    REGISTERED: leads.filter((l) => l.status === "REGISTERED").length,
    FOS_SELECTED: leads.filter((l) => l.status === "FOS_SELECTED").length,
    APPOINTMENT_BOOKED: leads.filter((l) => l.status === "APPOINTMENT_BOOKED").length,
    VISITED_FOS: leads.filter((l) => l.status === "VISITED_FOS").length,
    CONVERTED_TO_SPRO: leads.filter((l) => l.status === "CONVERTED_TO_SPRO").length,
    DROPPED: leads.filter((l) => l.status === "DROPPED").length,
    todaysAppointments: leads.filter(
      (l) =>
        l.appointmentDate === moment().format("YYYY-MM-DD") &&
        l.status === "APPOINTMENT_BOOKED"
    ).length,
  };

  return res.json({
    status: "SUCCESS",
    data: stats,
  });
});

/**
 * POST /api/fos/toggle-block
 * Toggle blocked state for a FOS/date availability row.
 */
server.post("/api/fos/toggle-block", (req, res) => {
  const { fosId, date } = req.body;
  if (!fosId || !date) {
    return res.status(400).json({
      status: "FAIL",
      message: "FOS ID and date are required.",
    });
  }

  const db = router.db;
  const fos = db.get("fos").find({ id: fosId, isDeleted: false }).value();
  if (!fos) {
    return res.status(404).json({
      status: "FAIL",
      message: "FOS not found.",
    });
  }

  const availability = db.get("fosAvailability").find({ fosId, date }).value();
  if (availability) {
    const nextBlocked = !availability.isBlocked;
    db.get("fosAvailability")
      .find({ id: availability.id })
      .assign({ isBlocked: nextBlocked })
      .write();
    return res.json({
      status: "SUCCESS",
      message: nextBlocked ? "Date blocked." : "Date unblocked.",
      data: {
        id: availability.id,
        fosId,
        date,
        isBlocked: nextBlocked,
      },
    });
  }

  const row = {
    id: "fa_" + Date.now(),
    fosId,
    date,
    maxCapacity: 10,
    currentBookings: 0,
    isBlocked: true,
  };
  db.get("fosAvailability").push(row).write();

  return res.json({
    status: "SUCCESS",
    message: "Date blocked.",
    data: row,
  });
});

/**
 * POST /api/fos/toggle-availability
 * Toggle overall availability for a FOS hub.
 */
server.post("/api/fos/toggle-availability", (req, res) => {
  const { fosId } = req.body;
  if (!fosId) {
    return res.status(400).json({
      status: "FAIL",
      message: "FOS ID is required.",
    });
  }

  const db = router.db;
  const fos = db.get("fos").find({ id: fosId, isDeleted: false }).value();
  if (!fos) {
    return res.status(404).json({
      status: "FAIL",
      message: "FOS not found.",
    });
  }

  const nextAvailable = fos.isAvailable === false;
  db.get("fos")
    .find({ id: fosId })
    .assign({ isAvailable: nextAvailable })
    .write();

  return res.json({
    status: "SUCCESS",
    message: nextAvailable ? "FOS is now available." : "FOS is now unavailable.",
    data: {
      fosId,
      isAvailable: nextAvailable,
    },
  });
});

// ============================================================
// Default json-server router (handles GET /fos, GET /leads, etc.)
// ============================================================
server.use(router);

// Start server on 0.0.0.0 (accessible from other devices on the same network)
const PORT = Number(process.env.PORT) || 4000;
server.listen(PORT, "0.0.0.0", () => {
  console.log(`\n🚀 Roz Kamao Mock Server running at:`);
  console.log(`   Local:   http://localhost:${PORT}`);
  console.log(`   Network: http://0.0.0.0:${PORT} (use your laptop IP)\n`);
  console.log(`📋 Custom API endpoints:`);
  console.log(`   POST /api/lead/login-context    → Resolve Roz/SPro login path`);
  console.log(`   POST /api/lead/send-otp        → Send OTP (always 1234)`);
  console.log(`   POST /api/lead/verify-otp       → Verify OTP`);
  console.log(`   POST /api/lead/register          → Submit basic details`);
  console.log(`   POST /api/lead/select-fos        → Select FOS`);
  console.log(`   POST /api/lead/book-appointment  → Book appointment`);
  console.log(`   POST /api/lead/cancel-booking    → Cancel booking`);
  console.log(`   POST /api/lead/reschedule        → Reschedule booking`);
  console.log(`   POST /api/lead/mark-visited      → Admin: mark visited`);
  console.log(`   POST /api/lead/convert-to-spro   → Admin: convert to SPro`);
  console.log(`   POST /api/lead/drop              → Admin: drop lead`);
  console.log(`   GET  /api/lead/stats             → Funnel stats`);
  console.log(`   POST /api/fos/toggle-block       → Block/unblock date`);
  console.log(`   POST /api/fos/toggle-availability→ Enable/disable FOS`);
  console.log(`\n📊 json-server default endpoints:`);
  console.log(`   GET  /leads`);
  console.log(`   GET  /fos`);
  console.log(`   GET  /fosAvailability`);
  console.log(`   GET  /fosAvailability?fosId=fos001\n`);
});
