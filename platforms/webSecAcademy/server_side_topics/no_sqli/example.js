const express = require('express')
const app = express()
const port = 3000

const mongoose = require("mongoose");

mongoose.connect("mongodb://localhost:27017/test");

const someMongooseModel = mongoose.model("def", {
    email: String,
    vn: Number,
 });

app.get("/get", async function (req, res) {
    const result = await someMongooseModel.find({ $where: `this.email === '${req.query.p}'`})
    console.log(result)

    res.send("done")
})

app.get("/create", async function (req, res) {
   const def = new someMongooseModel({
       email: 'jj',
       vn: 2
   });

   await def.save();

   res.send('ok');
});

app.listen(port, () => {
   console.log(`Example app listening on port ${port}`)
})
