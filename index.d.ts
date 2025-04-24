import { RequestHandler } from "express";

export interface WebWallOptions {
  xss?: boolean;
  nosqlInjection?: boolean;
  ban?: boolean;
  bruteForce?: boolean;
  credentialStuffing?: boolean;
  rateLimit?: false | {
    windowMs?: number;
    max?: number;
    message?: string;
    [key: string]: any;
  };
  openRedirect?: boolean;
  commandInjection?: boolean;
  jwt?: boolean | {
    algorithms?: string[];
  };
  jwtSecret?: string;
  // otpAbuse?:boolean;
  ddos?: false | {
    windowMs?: number;
    max?: number;
    message?: string;
  };
  directoryTraversal?: boolean | {
    baseDir?: string;
  };
  exposedFiles?:boolean;
  openPort?: boolean | {
    blockedPorts?: number[];
    paths?: string[];
  };
}

declare function webwall(options?: WebWallOptions): RequestHandler[];

export default webwall;
