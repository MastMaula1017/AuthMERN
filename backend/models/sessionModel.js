import mongoose from "mongoose";

const sessionSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
  }

});


const Session = mongoose.model("Session", sessionSchema);

export default Session;
