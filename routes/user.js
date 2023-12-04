var express = require("express");
var router = express.Router();

/* GET users listing. */
router.get("/", function (req, res, next) {
  res.send(
    `<html><head><head><body><h1> Hello World! You are in the user page. </h1></body></html>`
  );
});

router.post("/login", function (req, res, next) {
  console.log("req", req.body);
  const resJson = {
    statusCode: "1000",
    message: "OK",
    meta: {},
    data: {
      id: "368af3d3-45fb-11ed-9707-0242ac130002",
      email: req.body.email,
    },
  };
  res.status(200).json(resJson);
});

router.post("/signup", function (req, res, next) {
  console.log("req", req.body);
  const resJson = {
    statusCode: "1000",
    message: "OK",
    meta: {},
    data: {
      verifyKey:
        "NQM4CWVdYVZhADUHMFRhVjcaMwVhAGJQOVgzHmJTOQg5XGQAMh8xCWNbYVNhUDUYZlZhUzUBMgA2VzFSYVA5CzUFOAhlVWFT",
    },
  };
  res.status(201).json(resJson);
});

module.exports = router;
