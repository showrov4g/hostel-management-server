const express = require("express");
const app = express();
const cors = require("cors");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const port = process.env.PORT || 5000;

//middlewares

app.use(cors());
app.use(express.json());

// mongodb database

const {
  MongoClient,
  ServerApiVersion,
  ObjectId,
  ReturnDocument,
} = require("mongodb");
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@cluster0.23lvn.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    // await client.connect();
    // Send a ping to confirm a successful connection
    // await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
    //  collections
    const userCollection = client.db("hostel").collection("users");
    const mealCollection = client.db("hostel").collection("meals");
    const requestCollection = client.db("hostel").collection("request");
    const upcomingMealCollection = client.db("hostel").collection("upcoming");
    const reviewsCollection = client.db("hostel").collection("reviews");

    // json web token
    app.post("/jwt", async (req, res) => {
      const user = req.body;
      const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: "1h",
      });
      res.send({ token });
    });
    // middleware

    // token verify
    const verifyToken = (req, res, next) => {
      // console.log('inside verify token', req.headers.authorization);
      if (!req.headers.authorization) {
        return res.status(401).send({ message: "unauthorized access" });
      }
      const token = req.headers.authorization.split(" ")[1];
      jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) {
          return res.status(401).send({ message: "unauthorized access" });
        }
        req.decoded = decoded;
        next();
      });
    };

    // admin verification
    const verifyAdmin = async (req, res, next) => {
      const email = req.decoded.email;
      const query = { email: email };
      const user = await userCollection.findOne(query);
      const isAdmin = user?.role === "admin";
      if (!isAdmin) {
        return res.status(403).send({ message: "forbidden access" });
      }
      next();
    };
    // apis

    app.post("/users", async (req, res) => {
      const user = req.body;
      const result = await userCollection.insertOne(user);
      res.send(result);
    });

    // user data getting api

    app.get("/users", verifyToken, async (req, res) => {
      const result = await userCollection.find().toArray();
      res.send(result);
    });
    // -----------
    app.patch("/users", async (req, res) => {
      const email = req.body.email;
      const filter = { email: email };
      const updateDoc = {
        $set: {
          lastSignInTime: req.body?.lastSignInTime,
        },
      };
      const result = await userCollection.updateOne(filter, updateDoc);
      res.send(result);
    });

    // delete user
    app.delete("/users/:id", verifyToken, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await userCollection.deleteOne(query);
      res.send(result);
    });
    // make admin
    app.patch(
      "/users/admin/:id",
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        const id = req.params.id;
        const filter = { _id: new ObjectId(id) };
        const updatedDoc = {
          $set: {
            role: "admin",
          },
        };
        const result = await userCollection.updateOne(filter, updatedDoc);
        res.send(result);
      }
    );

    // get data using user email
    app.get("/users/:email", verifyToken, async (req, res) => {
      const email = req.params.email;
      const query = { email: email };
      const result = await userCollection.findOne(query);
      res.send(result);
    });
    // get admin data
    app.get("/users/admin/:email", verifyToken, async (req, res) => {
      const email = req.params.email;
      if (email !== req.decoded.email) {
        return res.status(403).send({ message: "Forbidden Access" });
      }
      const query = { email: email };
      const user = await userCollection.findOne(query);
      let admin = false;
      if (user) {
        admin = user?.role === "admin";
      }
      res.send({ admin });
    });
    // user search api making

    // user search API
    app.get("/user/search", verifyToken, verifyToken, async (req, res) => {
      const { email, name } = req.query;
      const query = {};
      if (email) {
        query.email = { $regex: email, $options: "i" };
      }
      if (name) {
        query.name = { $regex: name, $options: "i" };
      }
      const result = await userCollection.find(query).toArray();
      res.send(result);
    });

    //  login admin data gating api making
    app.get("/admin/:email", verifyToken, verifyAdmin, async (req, res) => {
      const email = req.params.email;
      const query = { email: email, role: "admin" };
      const adminData = await userCollection.findOne(query);
      res.send(adminData);
    });

    // meals related api

    // meal item add apis
    app.post("/meals", verifyToken, verifyAdmin, async (req, res) => {
      const meal = req.body;
      const result = await mealCollection.insertOne(meal);
      res.send(result);
    });
    // meals data gate with limit
    app.get("/meals", async (req, res) => {
      const meals = req.body;
      const limit = parseInt(req.query.limit) || 0;
      const result = await mealCollection.find(meals).limit(limit).toArray();
      res.send(result);
    });
    // meals gating by added email
    app.get("/meals/:email", verifyToken, async (req, res) => {
      const email = req.params.email;
      const query = { distributer_email: email };
      const result = await mealCollection.find(query).toArray();
      res.send(result);
    });

    // gating single item data
    app.get("/meals/meal/:id", verifyToken, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await mealCollection.findOne(query);
      res.send(result);
    });
    // meals details update
    app.patch("/meals/update/:id", async (req, res) => {
      const id = req.params.id;
      const updateData = req.body;
      const filter = { _id: new ObjectId(id) };
      const updateDoc = {
        $set: updateData,
      };
      const result = await mealCollection.updateOne(filter, updateDoc);
      res.send(result);
    });

    // meals delete api making
    app.delete(
      "/meals/delete/:id",
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const result = await mealCollection.deleteOne(query);
        res.send(result);
      }
    );
    // -----------
    // meals short by
    app.get("/meals/sorted-by-likes", async (req, res) => {
      const result = await mealCollection.find().sort({ likes: -1 }).toArray();
      res.send(result);
    });

    app.get("/meals/sorted-by-reviews", async (req, res) => {
      const result = await mealCollection
        .find()
        .sort({ reviews_count: -1 })
        .toArray();
      res.send(result);
    });
    // -----------

    // like data storing api making

    app.patch("/meals/like/:id", verifyToken, async (req, res) => {
      const mealId = req.params.id;
      const userId = req.body.userId;

      const filter = { _id: new ObjectId(mealId) };
      const meal = await mealCollection.findOne(filter);

      // already like
      const alreadyLiked = meal.likedBy?.includes(userId);

      let update;
      if (alreadyLiked) {
        update = {
          $pull: { likedBy: userId },
          $inc: { likes: -1 },
        };
      } else {
        update = {
          $addToSet: { likedBy: userId },
          $inc: { likes: 1 },
        };
      }

      const result = await mealCollection.updateOne(filter, update, {
        returnDocument: "after",
      });
      res.send(result);
    });

    // meal request api
    app.post("/meals/request", verifyToken, async (req, res) => {
      //  ===============
      const meal = req.body;
      const userEmail = req.decoded.email;
      const emailQuery = { email: userEmail };
      const user = await userCollection.findOne(emailQuery);
      if (!user.subscription) {
        return res
          .status(403)
          .send({ message: "Subscription required to request meals." });
      }
      const result = await requestCollection.insertOne(meal);
      res.send(result);
    });
    // meal request status update 
    app.patch('/meals/request/status/:id' ,verifyToken,async(req,res)=>{
      const id = req.params.id;
      const{status} = req.body;
      const filter = {_id: new ObjectId(id)}
      const updateDoc={
        $set:{
          status: "delivered"
        }
      }
      const result = await requestCollection.updateOne(filter, updateDoc)
      res.send(result)
    })
    // get all requested meals 
    app.get('/meals/request/all',verifyToken,verifyAdmin, async(req,res)=>{
      const result = await requestCollection.find().toArray()
      res.send(result)
    })
    // requested meal delate api
    app.delete("/meals/request/:id", verifyToken, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await requestCollection.deleteOne(query);
      res.send(result);
    });

    // ===============
    app.get("/meals/request/:email", verifyToken, async (req, res) => {
      const email = req.params.email;
      const query = { email: email };
      const result = await requestCollection.find(query).toArray();
      res.send(result);
    });


    // Add a review and update the review count for a product
    app.post("/meals/review/:productId", verifyToken, async (req, res) => {
      const productId = req.params.productId;
      const review = req.body;
      review.productId = productId;
      review.userId = req.decoded.email;
      const reviewResult = await reviewsCollection.insertOne(review);
      res.send(reviewResult);

      const filter = { _id: new ObjectId(productId) };
      const updateDoc = {
        $inc: { reviews_count: 1 },
      };

      const updateResult = await mealCollection.updateOne(filter, updateDoc);

      if (updateResult.modifiedCount > 0) {
        res.send({
          success: true,
          message:
            "Review added and product review count updated successfully.",
        });
      } else {
        res.status(500).send({
          success: false,
          message: "Failed to update the product review count.",
        });
      }
    });
    // reviews data gating 
    app.get('/reviews/:id',verifyToken,async(req,res)=>{
      const id = req.params.id;
      const query ={productId: id}
      const result = await reviewsCollection.find(query).toArray()
      res.send(result);
    })

    // rating id 
    // Add or update a meal rating
    app.post("/meals/rate/:id", verifyToken, async (req, res) => {
      const mealId = req.params.id;
      const { rating } = req.body;
      const userId = req.decoded.email;
    
      if (!rating || rating < 1 || rating > 5) {
        return res.status(400).send({ message: "Rating must be between 1 and 5." });
      }
    
      const filter = { _id: new ObjectId(mealId) };
      const update = {
        $push: { ratings: { userId, rating } },
      };
    
      // Update the rating
      const result = await mealCollection.updateOne(filter, update, { upsert: true });
    
      if (result.modifiedCount > 0) {
        // Fetch the updated ratings and calculate the average
        const meal = await mealCollection.findOne(filter);
        const ratings = meal.ratings;
    
        const averageRating = (ratings.reduce((sum, rating) => sum + rating.rating, 0) / ratings.length).toFixed(2);
    
       
        const updateAvgRating = await mealCollection.updateOne(filter, {
          $set: { averageRating },
        });
    
        if (updateAvgRating.modifiedCount > 0) {
          return res.send({ message: "Rating added/updated successfully!", averageRating });
        } else {
          return res.status(500).send({ message: "Failed to update average rating." });
        }
      } else {
        return res.status(500).send({ message: "Failed to update rating." });
      }
    });



    // user data gating for making a table 
  


    // get app reviews data
    app.get("/reviews", verifyToken, async (req, res) => {
      const review = req.body;
      const result = await reviewsCollection.find(review).toArray();
      res.send(result);
    });

    // reviews edit
    app.patch("/meals/review/:id", verifyToken, async (req, res) => {
      const id = req.params.id;
      const { reviewsText } = req.body;
      const filter = { _id: new ObjectId(id) };
      const updatedDoc = {
        $set: {
          reviewsText,
        },
      };
      const result = await reviewsCollection.updateOne(filter, updatedDoc);
      res.send(result);
    });
    // reviews delete api making
    app.delete("/meals/review/:id", verifyToken, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await reviewsCollection.deleteOne(query);
      res.send(result);
    });
    // reviews gating by email filter
    app.get("/meals/review/:email", verifyToken, async (req, res) => {
      const email = req.params.email;
      const query = { email: email };
      const result = await reviewsCollection.find(query).toArray();
      res.send(result);
    });

    // filter by category

    app.get("/meals/category/:category", async (req, res) => {
      const category = req.params.category;
      const filter = { category: category };
      const result = await mealCollection.find(filter).toArray();
      res.send(result);
    });
    // filter by Price api
    app.get("/meals/filter-price", async (req, res) => {
      const minPrice = parseInt(req.query.minPrice) || 0;
      const maxPrice = parseInt(req.query.maxPrice) || Number.MAX_VALUE;
      const filter = {
        price: {
          $gte: minPrice,
          $lte: maxPrice,
        },
      };
      const result = await mealCollection.find(filter).toArray();
      res.send(result);
    });

    // upcoming meals post
    app.post("/upcoming-meal", verifyToken, verifyAdmin, async (req, res) => {
      const upcomingMeal = req.body;
      const result = await upcomingMealCollection.insertOne(upcomingMeal);
      res.send(result);
    });
    // upcoming meal data gating
    app.get("/upcoming-meal", async (req, res) => {
      const upcomingMeal = req.body;
      const limit = parseInt(req.query.limit) || 0;
      const result = await upcomingMealCollection.find(upcomingMeal).limit(limit).toArray();
      res.send(result);
    });
    // get upcoming meals single data
    app.get("/upcoming-meal/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await upcomingMealCollection.findOne(query);
      res.send(result);
    });
    // get total number of users and how many user request for meals 
    app.get("/dashboard/stats", verifyToken, verifyAdmin, async (req, res) => {
      try {
        const totalUsers = await userCollection.countDocuments();
        const totalMeals = await mealCollection.countDocuments();
        const totalRequests = await requestCollection.countDocuments();
        const totalReviews = await reviewsCollection.countDocuments();
    
        res.send({
          totalUsers,
          totalMeals,
          totalRequests,
          totalReviews,
        });
      } catch (error) {
        res.status(500).send({ message: "Error fetching stats", error });
      }
    });
    
    




    // apis end
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

// mongodb database

// ===========
app.get("/", (req, res) => {
  res.send("server is running");
});

app.listen(port, () => {
  console.log("server is running on port", port);
});
