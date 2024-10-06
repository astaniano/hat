const express = require('express')
const app = express()
const port = 3000

const mongoose = require("mongoose");

mongoose.connect("mongodb://localhost:27017/test");

const productMongooseModel = mongoose.model("product", {
    category: String,
    released: Boolean
});

app.get("/get", async function (req, res) {
    const result = await productMongooseModel.find({ $where: `this.category === '${req.query.category}'`})
    console.log(result)

    res.send("done")
})

app.get("/create", async function (req, res) {
   const def = new productMongooseModel({
     category: 'Gift',
     released: false
   });

   await def.save();

   res.send('ok');
});

app.listen(port, () => {
   console.log(`Example app listening on port ${port}`)
})
