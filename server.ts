import type * as Party from "partykit/server";

export default class Server implements Party.Server {
  constructor(readonly room: Party.Room) {}

  async onRequest(req: Party.Request) {
    return new Response(JSON.stringify({
      message: "Hello from partykit-slot-test",
      room: this.room.id,
      timestamp: new Date().toISOString()
    }), {
      headers: { "Content-Type": "application/json" }
    });
  }

  async onConnect(connection: Party.Connection) {
    connection.send(JSON.stringify({
      type: "connected",
      room: this.room.id,
      timestamp: new Date().toISOString()
    }));
  }

  async onMessage(message: string, sender: Party.Connection) {
    this.room.broadcast(JSON.stringify({
      type: "broadcast",
      message,
      sender: sender.id,
      timestamp: new Date().toISOString()
    }));
  }
}

Server satisfies Party.Worker;
