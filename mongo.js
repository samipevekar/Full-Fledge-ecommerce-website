const mongoose=require("mongoose")
mongoose.connect("mongodb://127.0.0.1:27017/Ecommerce-login")
.then("connected successfully")
.catch("err")

//creating schema
const EcommerceSchema=new mongoose.Schema({
    name:{
        type:String,
        required:true
    },
    email:{
        type:String,
        required:true
    },
    tel:{
        type:String,
        required:true
    },
    password:{
        type:String,
        required:true
    }
})


const collection= new mongoose.model("users",EcommerceSchema)

module.exports=collection