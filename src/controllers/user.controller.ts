import { type Request, type Response } from "express";
import * as userService from "../services/user.service.js";

export async function getUsers(req: Request, res: Response) {
  const users = await userService.getUsers();
  res.json(users);
}