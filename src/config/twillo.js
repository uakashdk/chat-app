import Twilio from "twilio";
import dotenv from "dotenv"


dotenv.config();

const client  = Twilio(process.env.TWILIO_ACCOUNT_SID,process.env.TWILIO_AUTH_TOKEN);


export default client;