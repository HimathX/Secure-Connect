import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import { FaUser, FaLock } from "react-icons/fa";
import "./signuppage.css";

const Signup = () => {
    const navigate = useNavigate();
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [confirmPassword, setConfirmPassword] = useState("");
    const [errors, setErrors] = useState({});
    const [authError, setAuthError] = useState("");
    const [passwordStrength, setPasswordStrength] = useState("");
    const [successMessage, setSuccessMessage] = useState("");

    const validateUsername = (username) => {
        if (username.length < 8) return "Username must be at least 8 characters long";
        return "";
    };

    const validatePassword = (password) => {
        let strength = "Weak";
        if (password.length >= 8) {
            if (/[a-z]/.test(password) && /[A-Z]/.test(password) && /[^a-zA-Z0-9]/.test(password)) {
                strength = "Strong";
            } else if (/[a-z]/.test(password) && /[A-Z]/.test(password)) {
                strength = "Medium";
            }
        }

        setPasswordStrength(strength);

        if (password.length < 8) return "Password must be at least 8 characters long";
        if (!/[a-z]/.test(password)) return "Password must contain at least one lowercase letter";
        if (!/[A-Z]/.test(password)) return "Password must contain at least one uppercase letter";
        if (!/[^a-zA-Z0-9]/.test(password)) return "Password must contain at least one special character";
        return "";
    };

    const validateConfirmPassword = (confirmPassword) => {
        if (confirmPassword !== password) return "Passwords do not match";
        return "";
    };

    const handleSignup = async (e) => {
        e.preventDefault();
        setAuthError("");
    
        const newErrors = {
            username: validateUsername(username),
            password: validatePassword(password),
            confirm_password: validateConfirmPassword(confirmPassword),
        };
    
        setErrors(newErrors);
    
        if (!newErrors.username && !newErrors.password && !newErrors.confirm_password) {
            try {
                const response = await axios.post(
                    "http://127.0.0.1:8075/signup",
                    { username, password, confirm_password: confirmPassword },  
                    { headers: { "Content-Type": "application/json" } }
                );
                setSuccessMessage(response.data.message);
                setTimeout(() => navigate("http://127.0.0.1:8075/login"), 2000);
            } catch (error) {
                if (error.response && error.response.data && Array.isArray(error.response.data.detail)) {
                    setAuthError(error.response.data.detail.map(err => err.msg).join(", "));
                } else {
                    setAuthError(error.response?.data?.detail || "Signup failed. Please try again.");
                }
            }
        } else {
            setAuthError("Please fix the errors before proceeding.");
        }
    };
    

    return (
        <div className="wrapper2">
            <div className="form-box signup">
                <form onSubmit={handleSignup}>
                    <h1>Sign Up</h1>

                    <div className="input-box">
                        <input
                            type="text"
                            placeholder="Username"
                            value={username}
                            onChange={(e) => {
                                setUsername(e.target.value);
                                setErrors({ ...errors, username: validateUsername(e.target.value) });
                            }}
                            required
                        />
                        <FaUser className="icon" />
                        {errors.username && <p className="error-message">{errors.username}</p>}
                    </div>

                    <div className="input-box">
                        <input
                            type="password"
                            placeholder="Password"
                            value={password}
                            onChange={(e) => {
                                setPassword(e.target.value);
                                setErrors({ ...errors, password: validatePassword(e.target.value) });
                            }}
                            required
                        />
                        <FaLock className="icon" />
                        {errors.password && <p className="error-message">{errors.password}</p>}
                        {password && <p className={`password-strength ${passwordStrength.toLowerCase()}`}>Strength: {passwordStrength}</p>}
                    </div>

                    <div className="input-box">
                        <input
                            type="password"
                            placeholder="Confirm Password"
                            value={confirmPassword}
                            onChange={(e) => {
                                setConfirmPassword(e.target.value);
                                setErrors({ ...errors, confirm_password: validateConfirmPassword(e.target.value) });
                            }}
                            required
                        />
                        <FaLock className="icon" />
                        {errors.confirm_password && <p className="error-message">{errors.confirm_password}</p>}
                    </div>

                    {authError && <p className="auth-error">{authError}</p>}
                    {successMessage && <p className="success-message">{successMessage}</p>}

                    <button type="submit">Sign Up</button>
                </form>
            </div>
        </div>
    );
};

export default Signup;
