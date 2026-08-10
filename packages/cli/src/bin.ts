#!/usr/bin/env node
import { buildCli } from "./index.js";

buildCli().runExit(process.argv.slice(2));
