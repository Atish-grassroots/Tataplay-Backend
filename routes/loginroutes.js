const express = require("express");
const passport = require("passport");
const { getDb } = require("../config/connect");
const AgentsBiometric = require("../model/AgentsBiometric");
const { encrypt, decrypt } = require("../config/encryption");

const router = express.Router();
const ObjectId = require("mongodb").ObjectId;

// Set up the login route
// router.post('/login',
//   passport.authenticate('local', { failureRedirect: '/login-failure' }),
//   async function(req, res) {
//     const db = getDb();
//     try {
//       const user = await db.collection('UserMaster').findOne({ _id: req.user._id });
//       res.json(user);
//     } catch (error) {
//       res.status(500).send('Failed to retrieve user data');
//     }
//   }
// );
/**
 * @swagger
 * /login:
 *   post:
 *     summary: Login to the application
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Login successful
 *         content:
 *           application/json:
 *             schema:
 *
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Failed to process login
 *
 *
 *
 */
router.post(
  "/login",
  passport.authenticate("local", { failureRedirect: "/login-failure" }),
  async function (req, res) {
    const db = getDb();
    try {
      // Assuming req.user contains UserName and Password
      const name = req.user.UserName;
      const pass = req.user.Password;
      const user = await db
        .collection("UserMaster")
        .findOne({ UserName: name, Password: pass });

      if (user) {
        const aid = parseInt(user.id);
        // Insert into AgentsBiometric
        const insertResult = await db.collection("AgentsBiometric").insertOne({
          UserID: aid,
          AStartTime: new Date(),
          UserStatus: "Login",
          BreakStatus: "Login",
          TDate: new Date(),
        });
        // Store the insertedId in the user's session

        req.session.sessionId = insertResult.insertedId;

        // Update Users
        await db
          .collection("UserMaster")
          .updateOne(
            { id: aid },
            { $set: { agentstatus: "Logged In", agentstatustime: new Date() } }
          );

        // Retrieve the updated user information
        const updatedUser = await db
          .collection("UserMaster")
          .findOne({ id: aid });
        updatedUser.sessionId = req.session.sessionId;
        res.json(updatedUser);
      } else {
        res.status(401).send("User not found or not enabled");
      }
    } catch (error) {
      res.status(500).send("Failed to process login");
    }
  }
);

// router.post("/login", async function (req, res) {
//     const db = getDb();
//     try {
//       // Assuming req.body contains UserName and Password
//       const name = req.body.username;
//       const pass = req.body.password;
//      // console.log(req.body);
//       //console.log("pass1", name);
//       // Find the user by username only
//       const user = await db.collection("UserMaster").findOne({ UserName: name });

//       if (user) {
//         // Decrypt the stored password to compare
//         const decryptedPassword = decrypt(user.Password);
//        // console.log("pass", pass);
//         //console.log("decryptpass", decryptedPassword)

//         if (decryptedPassword === pass) {
//           const aid = parseInt(user.id);
//           // Insert into AgentsBiometric
//           const insertResult = await db.collection("AgentsBiometric").insertOne({
//             UserID: aid,
//             AStartTime: new Date(),
//             UserStatus: "Login",
//             BreakStatus: "Login",
//             TDate: new Date(),
//           });
//           // Store the insertedId in the user's session
//           req.session.sessionId = insertResult.insertedId;

//           // Update Users
//           await db
//             .collection("UserMaster")
//             .updateOne(
//               { id: aid },
//               { $set: { agentstatus: "Logged In", agentstatustime: new Date() } }
//             );

//           // Retrieve the updated user information
//           const updatedUser = await db
//             .collection("UserMaster")
//             .findOne({ id: aid });
//           updatedUser.sessionId = req.session.sessionId;
//           res.json(updatedUser);
//         } else {
//           res.status(401).send("Incorrect password");
//         }
//       } else {
//         res.status(401).send("User not found");
//       }
//     } catch (error) {
//       res.status(500).send("Failed to process login");
//     }
//   });

router.get("/login-failure", function (req, res) {
  res.send("Failed to login");
});

/**
 * @swagger
 *  /logout:
 *    post:
 *      summary: Logout from the application
 *      tags: [Authentication]
 *      requestBody:
 *        required: true
 *        content:
 *          application/json:
 *            schema:
 *              type: object
 *              properties:
 *                sessionId:
 *                  type: string
 *                  description: The session ID of the user's current session.
 *                userId:
 *                  type: string
 *                  description: The user's ID.
 *              required:
 *                - sessionId
 *                - userId
 *      responses:
 *        200:
 *          description: User logged out successfully
 *        400:
 *          description: Session ID and User ID are required
 *        404:
 *          description: No active session found to update logout time
 *        500:
 *          description: Failed to process logout
 *
 */
router.post("/logout", async function (req, res) {
  const { sessionId, userId } = req.body;

  if (!sessionId || !userId) {
    return res.status(400).send("Session ID and User ID are required");
  }

  console.log("logout user", sessionId);

  const db = getDb();
  try {
    const aid = parseInt(userId);
    const sessionObjectId = new ObjectId(sessionId);

    // Update logout time in AgentsBiometric
    const updateResult = await db
      .collection("AgentsBiometric")
      .findOneAndUpdate(
        { _id: sessionObjectId, UserID: aid },
        {
          $set: {
            AEndTime: new Date(),
            UserStatus: "Logout",
            BreakStatus: "Logout",
          },
        },
        { returnDocument: "after" }
      );

    if (!updateResult) {
      console.error(
        "No active session found to update logout time for user ID:",
        aid
      );
      return res
        .status(404)
        .send("No active session found to update logout time");
    }

    // Update Users
    await db
      .collection("UserMaster")
      .updateOne(
        { id: aid },
        { $set: { agentstatus: "Logged Out", agentstatustime: new Date() } }
      );

    res.send("User logged out successfully");
  } catch (error) {
    console.error(error);
    res.status(500).send("Failed to process logout");
  }
});

//   router.post('/break-in', async function(req, res) {
//     const db = getDb();
//     console.log('Request body:', req.body);
//     console.log('Request body1:', JSON.stringify(req.body));
//     const { breakType } = req.body;
//     console.log('user', req.user);

//     if (!req.user || !req.user._id) {
//       return res.status(400).send('No logged-in user to start break for');
//     }

//     try {
//       const aid = req.user._id;

//       // Insert break start into AgentsBiometric
//       const insertResult = await db.collection('AgentsBiometric').insertOne({
//         UserID: aid,
//         BreakStartTime: new Date(),
//         BreakStatus: breakType,
//         TDate: new Date()
//       });

//       // Store the insertedId in the user's session or another persistent storage
//       req.session.breakId = insertResult.insertedId;

//       console.log('Insert result:', insertResult);
//       res.status(200).send('Break started');
//     } catch (error) {
//       console.error('Error starting break:', error);
//       res.status(500).send('Failed to start break');
//     }
//   });

/**
 * @swagger
 * /register-break:
 *   post:
 *     summary: Register or end a break for a user
 *     tags:
 *       - Break Management
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               userId:
 *                 type: string
 *                 description: The ID of the user.
 *               breakType:
 *                 type: string
 *                 description: The type of break being registered.
 *               breakStatus:
 *                 type: string
 *                 description: Indicates whether the break is starting ("true") or ending ("false").
 *             required:
 *               - userId
 *               - breakType
 *               - breakStatus
 *     responses:
 *       200:
 *         description: Break successfully started or ended.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Break started or Break ended.
 *       400:
 *         description: No user ID provided.
 *       404:
 *         description: No active break session found to end.
 *       500:
 *         description: Failed to process break.
 */
router.post("/register-break", async function (req, res) {
  const db = getDb();
  console.log("Request body:", req.body);
  const { userId, breakType, breakStatus } = req.body;

  if (!userId) {
    return res.status(400).send("No user ID provided");
  }

  try {
    const aid = parseInt(userId);
    const currentTime = new Date().toTimeString().split(" ")[0];
    if (breakStatus === "true") {
      // Insert break start into AgentsBiometric
      const insertResult = await db.collection("AgentsBiometric").insertOne({
        UserID: aid,
        BreakStartTime: new Date(),
        BreakType: breakType,
        BreakStatus: breakType,
        TDate: new Date(),
      });

      // Store the insertedId in the user's session or another persistent storage
      req.session.breakId = insertResult.insertedId;

      console.log("Insert result:", insertResult);
      res.status(200).send("Break started");
    } else {
      // Find the latest break-in record and update it with the break-out time
      const updateResult = await db
        .collection("AgentsBiometric")
        .findOneAndUpdate(
          { UserID: aid, BreakEndTime: { $exists: false } },
          { $set: { BreakEndTime: new Date(), BreakStatus: "BreakOut" } },
          { sort: { BreakStartTime: -1 }, returnDocument: "after" }
        );

      if (!updateResult) {
        return res.status(404).send("No active break session found to end");
      }

      console.log("Update result:", updateResult);
      res.status(200).send("Break ended");
    }
  } catch (error) {
    console.error("Error processing break:", error);
    res.status(500).send("Failed to process break");
  }
});

router.get("/break-records", async function (req, res) {
  const db = getDb();
  try {
    // Assuming 'UserID' in 'AgentsBiometric' references 'id' in 'UserMaster'
    // and 'UserName' is a field in 'UserMaster' you want to retrieve
    const breakRecords = await db
      .collection("AgentsBiometric")
      .aggregate([
        {
          $lookup: {
            from: "UserMaster",
            localField: "UserID",
            foreignField: "id",
            as: "userDetails",
          },
        },
        {
          $unwind: "$userDetails",
        },
        {
          $project: {
            _id: 0,
            userId: "$UserID",
            name: "$userDetails.UserName",
            breakType: "$BreakType",
            startTime: "$BreakStartTime",
            endTime: "$BreakEndTime",
            duration: {
              $subtract: ["$BreakEndTime", "$BreakStartTime"],
            },
          },
        },
      ])
      .toArray();

    res.json(breakRecords);
  } catch (error) {
    console.error("Failed to retrieve break records:", error);
    res.status(500).send("Failed to retrieve break records");
  }
});

/**
 * @swagger
 *   /user-report:
 *  get:
 *    summary: Retrieve a report of user activities within a specified date
 *    tags:
 *      - User Reports
 *    parameters:
 *      - in: query
 *        name: date
 *        schema:
 *          type: string
 *          format: date
 *        required: true
 *        description: The date for which the report is requested, in 'YYYY-MM-DD' format.
 *    responses:
 *      200:
 *        description: Successfully retrieved user report
 *        content:
 *          application/json:
 *            schema:
 *              type: object
 *              properties:
 *                userId:
 *                  type: string
 *                  description: The ID of the user.
 *                name:
 *                  type: string
 *                  description: The name of the user.
 *                loginDuration:
 *                  type: integer
 *                  description: Total duration of all logins in milliseconds.
 *                loginAttempts:
 *                  type: integer
 *                  description: The number of login attempts.
 *                breakDuration:
 *                  type: integer
 *                  description: Total duration of all breaks in milliseconds.
 *                breakAttempts:
 *                  type: integer
 *                  description: The number of break attempts.
 *                firstLoginTime:
 *                  type: string
 *                  format: date-time
 *                  description: The time of the first login.
 *                lastLogoutTime:
 *                  type: string
 *                  format: date-time
 *                  description: The time of the last logout.
 *      400:
 *        description: Date parameter is missing or invalid
 *      500:
 *        description: Failed to retrieve user report
 */
router.get("/user-report", async function (req, res) {
  const db = getDb();
  const date = new Date(req.query.date);
  const nextDay = new Date(date);
  nextDay.setDate(date.getDate() + 1);

  try {
    const userReport = await db.collection("AgentsBiometric").aggregate([
        {
          $lookup: {
            from: "UserMaster",
            let: { userId: "$UserID" },
            pipeline: [
              {
                $match: {
                  $expr: {
                    $and: [
                      { $eq: ["$id", "$$userId"] },
                      { $eq: ["$Profile", 1] },
                    ],
                  },
                },
              },
            ],
            as: "userDetails",
          },
        },
        { $unwind: "$userDetails" },
        {
          $match: {
            TDate: {
              $gte: date,
              $lt: nextDay,
            },
          },
        },
        {
          $group: {
            _id: "$UserID",
            name: { $first: "$userDetails.UserName" },
            firstLoginTime: { $min: "$AStartTime" },
            lastLogoutTime: {$max: {$cond: [{ $lt: ["$AEndTime", nextDay] }, "$AEndTime", null],},},
            loginDuration: {$sum: { $subtract: ["$AEndTime", "$AStartTime"] },},
            loginAttempts: {$sum: {$cond: [{$and: [{ $ne: ["$AStartTime", null] },{ $ne: ["$AEndTime", null] },{$or: [{ $eq: ["$UserStatus", "Login"] },{ $eq: ["$UserStatus", "Logout"] }, ],
                      },
                    ],
                  },
                  1,
                  0,
                ],
              },
            },
            breakDuration: {
              $sum: { $subtract: ["$BreakEndTime", "$BreakStartTime"] },
            },
            breakAttempts: {
              $sum: {
                $cond: [
                  {
                    $and: [
                      { $ne: ["$BreakStartTime", null] },
                      {
                        $or: [
                          { $eq: ["$BreakType", "TEA"] },
                          { $eq: ["$BreakType", "LUNCH"] },
                          { $eq: ["$BreakType", "TRAINING"] },
                        ],
                      },
                    ],
                  },
                  1,
                  0,
                ],
              },
            },
          },
        },
        {
          $project: {
            _id: 0,
            userId: "$_id",
            name: 1,
            loginDuration: {
              $let: {
                vars: {
                  hours: {
                    $floor: { $divide: ["$loginDuration", 1000 * 60 * 60] },
                  },
                  minutes: {
                    $floor: {
                      $mod: [{ $divide: ["$loginDuration", 1000 * 60] }, 60],
                    },
                  },
                  seconds: {
                    $floor: {
                      $mod: [{ $divide: ["$loginDuration", 1000] }, 60],
                    },
                  },
                },
                in: {
                  $concat: [
                    { $toString: "$$hours" },
                    ":",
                    { $toString: "$$minutes" },
                    ":",
                    { $toString: "$$seconds" },
                  ],
                },
              },
            },
            loginAttempts: 1,
            breakDuration: {
              $let: {
                vars: {
                  hours: {
                    $floor: { $divide: ["$breakDuration", 1000 * 60 * 60] },
                  },
                  minutes: {
                    $floor: {
                      $mod: [{ $divide: ["$breakDuration", 1000 * 60] }, 60],
                    },
                  },
                  seconds: {
                    $floor: {
                      $mod: [{ $divide: ["$breakDuration", 1000] }, 60],
                    },
                  },
                },
                in: {
                  $concat: [
                    { $toString: "$$hours" },
                    ":",
                    { $toString: "$$minutes" },
                    ":",
                    { $toString: "$$seconds" },
                  ],
                },
              },
            },
            breakAttempts: 1,
            firstLoginTime: 1,
            lastLogoutTime: 1,
          },
        },
      ])
      .toArray();

    res.json(userReport);
  } catch (error) {
    console.error("Failed to retrieve user report:", error);
    res.status(500).send("Failed to retrieve user report");
  }
});

/**
 * @swagger
 *    /get-user:
 *  get:
 *    summary: Retrieve all users with profile 1
 *    tags:
 *      - Users
 *    responses:
 *      200:
 *        description: Successfully retrieved users with profile 1
 *        content:
 *          application/json:
 *            schema:
 *              type: array
 *              items:
 *                type: object
 *                properties:
 *                  _id:
 *                    type: string
 *                    description: The ID of the user.
 *                  UserName:
 *                    type: string
 *                    description: The name of the user.
 *                  profile:
 *                    type: integer
 *                    description: The profile ID of the user, which is 1 for all users returned by this API.
 *      500:
 *        description: Failed to retrieve users
 */
router.get("/get-user", async function (req, res) {
  const db = getDb();
  try {
    const usersWithProfileOne = await db
      .collection("UserMaster")
      .find({ Profile: 1 })
      .toArray();
    res.json(usersWithProfileOne);
  } catch (error) {
    console.error("Failed to retrieve users with profile 1:", error);
    res.status(500).send("Failed to retrieve users");
  }
});

router.get("/get-user1", async function (req, res) {
  const db = getDb();
  try {
    let usersWithProfileOne = await db
      .collection("UserMaster")
      .find({ Profile: 1 })
      .toArray();

    // Decrypt passwords for each user
    usersWithProfileOne = usersWithProfileOne.map((user) => {
      const decryptedPassword = decrypt(user.Password);
      return { ...user, Password: decryptedPassword };
    });

    res.json(usersWithProfileOne);
  } catch (error) {
    console.error("Failed to retrieve users with profile 1:", error);
    res.status(500).send("Failed to retrieve users");
  }
});

/**
 * @swagger
 *   /add-user:
 *  post:
 *    summary: Add a new user to UserMaster
 *    tags:
 *      - Users
 *    requestBody:
 *      required: true
 *      content:
 *        application/json:
 *          schema:
 *            type: object
 *            properties:
 *              EmployeeName:
 *                type: string
 *                description: The name of the employee.
 *              UserName:
 *                type: string
 *                description: The username for the user.
 *              UserPhone:
 *                type: string
 *                description: The phone number of the user.
 *              Password:
 *                type: string
 *                description: The password for the user account.
 *              EmailID:
 *                type: string
 *                description: The email ID of the user.
 *            required:
 *              - EmployeeName
 *              - UserName
 *              - UserPhone
 *              - Password
 *              - EmailID
 *    responses:
 *      200:
 *        description: User added successfully
 *        content:
 *          application/json:
 *            schema:
 *              type: object
 *              properties:
 *                message:
 *                  type: string
 *                  example: User added successfully.
 *                userId:
 *                  type: string
 *                  description: The newly created user ID.
 *      400:
 *        description: Missing required fields or invalid data provided
 *      500:
 *        description: Failed to add the user
 */

router.post("/add-user", async function (req, res) {
  const db = getDb();
  const { EmployeeName, UserName, UserPhone, Password, EmailID } = req.body;

  // Validate the input
  if (!EmployeeName || !UserName || !UserPhone || !Password || !EmailID) {
    return res.status(400).send("All fields are required");
  }
  const encryptedPassword = encrypt(Password);

  try {
    // Generate a new ID based on the last user's ID
    const lastUser = await db
      .collection("UserMaster")
      .find()
      .sort({ id: -1 })
      .limit(1)
      .toArray();
    const newId = lastUser.length > 0 ? lastUser[0].id + 1 : 1;

    // Insert the new user with profile set to 1
    const newUser = {
      id: newId,
      EmployeeName,
      UserName,
      UserPhone,
      Password: encryptedPassword,
      EmailID,
      Profile: 1,
      Enabled: 1,
    };

    const result = await db.collection("UserMaster").insertOne(newUser);

    if (result.acknowledged) {
      res.status(200).json({
        message: "User added successfully",
        userId: result.insertedId,
      });
    } else {
      throw new Error("Failed to insert user");
    }
  } catch (error) {
    console.error("Failed to add user:", error);
    res.status(500).send("Failed to add user");
  }
});

/**
 * @swagger
 *   /edit-user/{userId}:
 *  put:
 *    summary: Update user details
 *    tags:
 *      - Users
 *    parameters:
 *      - in: path
 *        name: userId
 *        required: true
 *        schema:
 *          type: integer
 *        description: The ID of the user to update
 *    requestBody:
 *      required: true
 *      content:
 *        application/json:
 *          schema:
 *            type: object
 *            properties:
 *              EmployeeName:
 *                type: string
 *                description: The name of the employee.
 *              UserName:
 *                type: string
 *                description: The username for the user.
 *              UserPhone:
 *                type: string
 *                description: The phone number of the user.
 *              Password:
 *                type: string
 *                description: The password for the user account.
 *              EmailID:
 *                type: string
 *                description: The email ID of the user.
 *              Enabled:
 *                type: integer
 *                description: Indicates if the user is enabled (1) or disabled (0).
 *            required:
 *              - EmployeeName
 *              - UserName
 *              - UserPhone
 *              - Password
 *              - EmailID
 *              - Enabled
 *    responses:
 *      200:
 *        description: User updated successfully
 *        content:
 *          application/json:
 *            schema:
 *              type: object
 *              properties:
 *                message:
 *                  type: string
 *                  example: User updated successfully.
 *                user:
 *                  type: object
 *                  properties:
 *                    id:
 *                      type: integer
 *                    EmployeeName:
 *                      type: string
 *                    UserName:
 *                      type: string
 *                    UserPhone:
 *                      type: string
 *                    Password:
 *                      type: string
 *                    EmailID:
 *                      type: string
 *                    Enabled:
 *                      type: integer
 *      400:
 *        description: Missing required fields or invalid data provided
 *      404:
 *        description: User not found
 *      500:
 *        description: Failed to update user
 */
router.put("/edit-user/:userId", async function (req, res) {
  const db = getDb();
  const userId = parseInt(req.params.userId);
  const { EmployeeName, UserName, UserPhone, Password, EmailID } = req.body;
  let { Enabled } = req.body;

  // Convert Enabled to an integer
  Enabled = parseInt(Enabled);

  if (
    !EmployeeName ||
    !UserName ||
    !UserPhone ||
    !Password ||
    !EmailID ||
    Enabled === undefined
  ) {
    return res.status(400).send("All fields including Enabled are required");
  }
 // const encryptedPassword = encrypt(Password);

  try {
    const updateResult = await db.collection("UserMaster").updateOne(
      { id: userId },
      {
        $set: {
          EmployeeName,
          UserName,
          UserPhone,
          Password,
          EmailID,
          Enabled,
        },
      }
    );

    if (updateResult.matchedCount === 0) {
      return res.status(404).send("User not found");
    }

    if (updateResult.modifiedCount === 1) {
      const updatedUser = await db
        .collection("UserMaster")
        .findOne({ id: userId });
    //   updatedUser.Password = decrypt(updatedUser.Password);

      res
        .status(200)
        .json({ message: "User updated successfully", user: updatedUser });
    } else {
      throw new Error("Failed to update user");
    }
  } catch (error) {
    console.error("Failed to update user:", error);
    res.status(500).send("Failed to update user");
  }
});

// router.get('/login-success', async function(req, res) {
//     const db = getDb();
//     console.log(req.user.id);
//     try {
//        // console.log(req.user.id);
//       const users = await db.collection('UserMaster').find({}).toArray();
//       res.json(users);
//     } catch (error) {
//       res.status(500).send('Failed to retrieve users');
//     }
//   });

// Export the router
module.exports = router;
