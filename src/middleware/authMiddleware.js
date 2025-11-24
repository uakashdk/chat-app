import jwt from "jsonwebtoken";

export const authMiddleware = (req,res,next)=>{
    try {
         const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized",
      });
    }
    const token = authHeader.split(" ")[1];

    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

    req.user = decoded;
    next();
    } catch (error) {
        console.log("error",error);
        return res.status(401).json({success:false,message:"Invalid or expired token"})
    }
}