import net from "node:net";

const server = net
  .createServer(async (socket) => {
    const errCallback = (e) => {
      console.log("ffff error");
    };
    socket.on("error", errCallback);
    socket.on("readable", onReadable);

    async function onReadable() {
      let chunk;
      while (null !== (chunk = socket.read())) {
        console.log(chunk.toString());
      }
      socket.removeListener("error", errCallback);
      socket.removeListener("readable", onReadable);
      socket.end();
    }
  })
  .on("error", (err) => {
    throw err;
  });

const port = 3333;
server.listen(port, () => {
  console.log(`started on port ${port}`);
});
