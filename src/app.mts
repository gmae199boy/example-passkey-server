import express, { Router } from "express";
import Session from "express-session";
import redis from "redis";
import RedisStore from "connect-redis";
import cors from "cors";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import {
  AuthenticationResponseJSON,
  RegistrationResponseJSON,
} from "@simplewebauthn/types";
import { isoBase64URL, isoUint8Array } from "@simplewebauthn/server/helpers";

import { AppDataSource, dataSourceInit } from "./datasource.mjs";
import * as Entities from "./Entities/index.mjs";

const REDIS_URL = "redis://localhost:6379";
// process.env.REDIS_HOST ||
// (console.error("REDIS_HOST is required"), process.exit(1));
const RPID = "localhost";
const RP_NAME = "TEST_RP";
const ORIGIN = `http://localhost:5500`;
const AUTHENTICATOR_ATTACHMENT = "platform";
const TYPE = "public-key";

const app = express();
const router = Router();
const redisClient = redis.createClient({
  url: REDIS_URL,
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({ origin: "http://localhost:3000", credentials: true }));
app.use(
  Session({
    resave: false,
    saveUninitialized: false,
    secret: "secret",
    credentials: true,
    cookie: {
      httpOnly: false,
      sameSite: "none",
      secure: false,
    },
    store: new RedisStore({
      client: redisClient,
    }),
  })
);

router.post("/signup", async (req, res) => {
  try {
    const { email, pw, displayName } = req.body;

    if (pw.length < 8) {
      return res.status(400).json({
        error: {
          errorCode: -1001,
          errorMsg: "ERR_SHORT_PWD",
        },
      });
    }

    const user = await AppDataSource.getRepository(Entities.User).findOne({
      where: { email: req.body.email },
    });
    if (user) {
      return res.status(400).json({
        error: {
          errorCode: -1000,
          errorMsg: "ERR_DUPLICATED_EMAIL",
        },
      });
    }

    await AppDataSource.getRepository(Entities.User).insert({
      email,
      pw,
      displayName,
      name: email.split("@")[0],
    });

    req.session.user = user;

    return res.status(201).json({ error: null, user: { email } });
  } catch (e) {
    console.error(e);
    return res.status(500).json({
      error: {
        errorCode: -10000,
        errorMsg: "UNEXPECTED_ERROR",
      },
    });
  }
});

router.post("/signin", async (req, res) => {
  try {
    const { email, pw } = req.body;

    const user = await AppDataSource.getRepository(Entities.User).findOne({
      where: { email, pw },
    });
    if (!user) {
      return res.status(400).json({
        error: {
          errorCode: -1003,
          errorMsg: "ERR_INCORRECT_PW_OR_EMAIL",
        },
      });
    }

    req.session.user = user;

    return res.status(201).json({ error: null, user: { email } });
  } catch (e) {
    console.error(e);
    return res.status(500).json({
      error: {
        errorCode: -10000,
        errorMsg: "UNEXPECTED_ERROR",
      },
    });
  }
});

router.get("/user/passkey/register", async (req, res, next) => {
  try {
    const user = req.session.user;
    if (!user) {
      return res.status(401).send({
        error: {
          errorCode: -1002,
          errorMsg: "ERR_REQUIRED_LOGIN",
        },
      });
    }

    const credentials = await AppDataSource.getRepository(
      Entities.Passkey
    ).find({
      where: { userId: user.id },
    });

    const options = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RPID,
      userName: user.name,
      userID: isoUint8Array.fromUTF8String(user.id),
      userDisplayName: user.displayName,
      attestationType: "none",
      timeout: 300000, // 5분
      excludeCredentials: credentials.map((cred) => ({
        id: cred.credentialId,
        transports: cred.transports.split(",").flat() as (
          | "ble"
          | "cable"
          | "hybrid"
          | "internal"
          | "nfc"
          | "smart-card"
          | "usb"
        )[], // AuthenticatorTransportFuture[]
      })),
      authenticatorSelection: {
        authenticatorAttachment: AUTHENTICATOR_ATTACHMENT,
        residentKey: "preferred",
        userVerification: "preferred",
      },
    });

    req.session.challenge = options.challenge;

    return res.json({
      error: null,
      challenge: options.challenge,
      rp: { name: RP_NAME, id: RPID },
      user: {
        id: options.user.id,
        displayName: options.user.displayName,
        name: options.user.name,
      },
      pubKeyCredParams: options.pubKeyCredParams,
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({
      error: {
        errorCode: -10000,
        errorMsg: "UNEXPECTED_ERROR",
      },
    });
  }
});

router.post("/user/passkey/register", async (req, res) => {
  const expectedChallenge = req.session.challenge;
  const expectedOrigin = ORIGIN;
  const expectedRPID = RPID;
  const response: RegistrationResponseJSON = {
    id: req.body.credentialId,
    rawId: req.body.credentialRawId,
    type: TYPE,
    authenticatorAttachment: AUTHENTICATOR_ATTACHMENT,
    response: {
      clientDataJSON: req.body.clientDataJSON,
      attestationObject: req.body.attestationObject,
      transports: req.body.transports,
    },
    clientExtensionResults: {},
  };

  try {
    const user = req.session.user;
    if (!user) {
      return res.status(401).send({
        error: {
          errorCode: -1002,
          errorMsg: "ERR_REQUIRED_LOGIN",
        },
      });
    }

    const { verified, registrationInfo } = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin,
      expectedRPID,
      requireUserVerification: false,
    });
    if (!verified) {
      return res.status(400).json({
        error: {
          errorCode: -2000,
          errorMsg: "ERR_VERIFY_FAILED",
        },
      });
    }

    await AppDataSource.getRepository(Entities.Passkey).insert({
      credentialId: registrationInfo.credential.id,
      publicKey: isoBase64URL.fromBuffer(registrationInfo.credential.publicKey),
      userId: user.id,
      counter: registrationInfo.credential.counter,
      backedUp: registrationInfo.credentialBackedUp,
      deviceType: registrationInfo.credentialDeviceType,
      transports: response.response.transports.join(","),
    });

    delete req.session.challenge;

    return res.json({
      error: null,
      credentialId: registrationInfo.credential.id,
    });
  } catch (e) {
    delete req.session.challenge;

    console.error(e);
    return res.status(500).json({
      error: {
        errorCode: -10000,
        errorMsg: "UNEXPECTED_ERROR",
      },
    });
  }
});

router.get("/signin/passkey", async (req, res) => {
  try {
    const options = await generateAuthenticationOptions({
      rpID: RPID,
      timeout: 300000,
      allowCredentials: [],
      userVerification: "preferred",
    });

    req.session.challenge = options.challenge;

    return res.json({
      error: null,
      challenge: options.challenge,
      rpId: RPID,
      timeout: 300000,
      userVerification: options.userVerification,
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({
      error: {
        errorCode: -10000,
        errorMsg: "UNEXPECTED_ERROR",
      },
    });
  }
});

router.post("/signin/passkey", async (req, res) => {
  const expectedChallenge = req.session.challenge;
  const expectedOrigin = ORIGIN;
  const expectedRPID = RPID;
  const response: AuthenticationResponseJSON = {
    id: req.body.credentialId,
    rawId: req.body.credentialRawId,
    type: TYPE,
    authenticatorAttachment: AUTHENTICATOR_ATTACHMENT,
    clientExtensionResults: {},
    response: {
      clientDataJSON: req.body.clientDataJSON,
      authenticatorData: req.body.authenticatorData,
      signature: req.body.signature,
      userHandle: req.body.userHandle,
    },
  };

  try {
    const cred = await AppDataSource.getRepository(Entities.Passkey).findOne({
      where: { credentialId: response.id },
    });
    if (!cred) {
      return res.status(400).json({
        error: {
          errorCode: -2001,
          errorMsg: "ERR_NOT_FOUND_CRED",
        },
      });
    }
    const existUser = await AppDataSource.getRepository(Entities.User).findOne({
      where: { id: cred.userId },
    });
    if (!existUser) {
      return res.status(400).json({
        error: {
          errorCode: -1004,
          errorMsg: "ERR_NOT_FOUND_USER",
        },
      });
    }

    const authenticator = {
      publicKey: isoBase64URL.toBuffer(cred.publicKey),
      id: isoBase64URL.toBase64(cred.id.toString()),
      transports: cred.transports.split(",").flat() as (
        | "ble"
        | "cable"
        | "hybrid"
        | "internal"
        | "nfc"
        | "smart-card"
        | "usb"
      )[], // AuthenticatorTransportFuture[]
      counter: cred.counter,
    };

    const { verified, authenticationInfo } = await verifyAuthenticationResponse(
      {
        response,
        expectedChallenge,
        expectedOrigin,
        expectedRPID,
        credential: authenticator,
        requireUserVerification: false,
      }
    );
    if (!verified) {
      return res.status(400).json({
        error: {
          errorCode: -2000,
          errorMsg: "ERR_VERIFY_FAILED",
        },
      });
    }

    req.session.user = existUser;

    const { newCounter } = authenticationInfo;
    await AppDataSource.getRepository(Entities.Passkey).update(
      { id: cred.id },
      { counter: newCounter }
    );

    delete req.session.challenge;

    return res.json({ error: null, status: "loginSuccess" });
  } catch (e) {
    delete req.session.challenge;

    console.error(e);
    return res.status(500).json({
      error: {
        errorCode: -10000,
        errorMsg: "UNEXPECTED_ERROR",
      },
    });
  }
});

app.use(router);

app.listen(3000, async () => {
  redisClient.on("error", (error) => {
    console.error("Redis error:", error);
  });

  redisClient.on("connect", () => {
    console.log("Redis connected");
  });

  redisClient.on("ready", () => {
    console.log("Redis ready");
  });

  await dataSourceInit({ logging: false });
  await redisClient.connect();

  console.log("Server is running on port 3000");
});
