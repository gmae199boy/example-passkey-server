import express, { Router } from "express";
import cors from "cors";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import { isoBase64URL, isoUint8Array } from "@simplewebauthn/server/helpers";

const app = express();
const router = Router();

const userId = Math.random().toString(36).split(".")[1];
const email = Math.random().toString(36).split(".")[1] + "@gmail.com";

// DB 대용
const Credentials: Passkey[] = [];
const User: UserModel = { id: userId, username: email };

type UserModel = {
  id: string;
  username: string;
};

/**
 * It is strongly advised that credentials get their own DB
 * table, ideally with a foreign key somewhere connecting it
 * to a specific UserModel.
 *
 * "SQL" tags below are suggestions for column data types and
 * how best to store data received during registration for use
 * in subsequent authentications.
 */
type Passkey = {
  // SQL: Store as `TEXT`. Index this column
  id: string;
  // SQL: Store raw bytes as `BYTEA`/`BLOB`/etc...
  //      Caution: Node ORM's may map this to a Buffer on retrieval,
  //      convert to Uint8Array as necessary
  publicKey: string;
  // SQL: Foreign Key to an instance of your internal user model
  userId: string;
  // SQL: Store as `TEXT`. Index this column. A UNIQUE constraint on
  //      (webAuthnUserID + user) also achieves maximum user privacy
  webauthnUserID: string;
  // SQL: Consider `BIGINT` since some authenticators return atomic timestamps as counters
  counter: number;
  // SQL: `VARCHAR(32)` or similar, longest possible value is currently 12 characters
  // Ex: 'singleDevice' | 'multiDevice'
  deviceType: string;
  // SQL: `BOOL` or whatever similar type is supported
  backedUp: boolean;
  // SQL: `VARCHAR(255)` and store string array as a CSV string
  // Ex: ['ble' | 'cable' | 'hybrid' | 'internal' | 'nfc' | 'smart-card' | 'usb']
  transports?: any[];
};

let session = {
  id: userId,
  name: email,
  displayName: "t",
  challenge: "",
};

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

router.get("/auth/registerRequest", async (req, res, next) => {
  const user = session;

  try {
    const options = await generateRegistrationOptions({
      rpName: "TEST_RP",
      rpID: "fingerlabs.github.io",
      userID: isoUint8Array.fromUTF8String(user.id),
      userName: user.name,
      userDisplayName: user.displayName || "",
      attestationType: "none",
      excludeCredentials: Credentials,
      authenticatorSelection: {
        authenticatorAttachment: "platform",
        residentKey: "preferred",
        userVerification: "preferred",
      },
    });

    session.challenge = options.challenge;
    console.log("register options", options);
    return res.json(options);
  } catch (e) {
    console.error(e);
    return res.status(400).send({ error: e.message });
  }
});

router.post("/auth/registerResponse", async (req, res) => {
  const expectedChallenge = session.challenge;
  const expectedOrigin = "https://fingerlabs.github.io";
  const expectedRPID = "fingerlabs.github.io";
  const response = req.body.credential;
  console.log("register front response", response);
  try {
    const { verified, registrationInfo } = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin,
      expectedRPID,
      requireUserVerification: false,
    });
    if (!verified) {
      throw new Error("Verification failed.");
    }

    // Existing, signed-in user
    const user = session;

    Credentials.push({
      id: registrationInfo.credential.id,
      publicKey: isoBase64URL.fromBuffer(registrationInfo.credential.publicKey),
      userId: user.id,
      counter: registrationInfo.credential.counter,
      webauthnUserID: user.id,
      backedUp: registrationInfo.credentialBackedUp,
      deviceType: registrationInfo.credentialDeviceType,
      transports: response.response.transports,
    });

    delete session.challenge;
    console.log("register response", registrationInfo);
    return res.json({ user, registrationInfo, registrationSuccess: true });
  } catch (e) {
    delete session.challenge;

    console.error(e);
    return res
      .status(400)
      .send({ error: e.message, registrationSuccess: false });
  }
});

router.get("/auth/signinRequest", async (req, res) => {
  try {
    const options = await generateAuthenticationOptions({
      rpID: "fingerlabs.github.io",
      allowCredentials: Credentials,
    });

    session.challenge = options.challenge;

    console.log("signin options", options);

    return res.json(options);
  } catch (e) {
    console.error(e);
    return res.status(400).json({ error: e.message });
  }
});

router.post("/auth/signinResponse", async (req, res) => {
  const response = req.body.credential;
  const expectedChallenge = session.challenge;
  const expectedOrigin = "https://fingerlabs.github.io";
  const expectedRPID = "fingerlabs.github.io";
  const user = session;
  console.log("signin front response", response);
  try {
    const cred = Credentials.filter((cred) => cred.id === response.id);
    if (cred.length === 0) {
      throw new Error("Credential not found.");
    }
    const existUser = User.id === user.id;
    if (!existUser) {
      throw new Error("User not found.");
    }

    // Base64URL decode some values
    const authenticator = {
      publicKey: isoBase64URL.toBuffer(cred[0].publicKey),
      id: isoBase64URL.toBase64(cred[0].id),
      transports: cred[0].transports,
      counter: cred[0].counter,
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
      throw new Error("User verification failed.");
    }
    console.log("signin response", authenticationInfo);
    const { newCounter } = authenticationInfo;
    cred[0].counter = newCounter;

    delete session.challenge;

    return res.json({ authenticationInfo, loginSuccess: true });
  } catch (e) {
    delete session.challenge;

    console.error(e);
    return res.status(400).json({ error: e.message, loginSuccess: false });
  }
});

app.use(router);

app.listen(3000, () => {
  console.log("Server is running on port 3000");
});
