import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import './loginpage.css';
import { FaUser, FaLock } from "react-icons/fa";

const LoginRegister = () => {
    const navigate = useNavigate();
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [rememberMe, setRememberMe] = useState(false);
    const [error, setError] = useState("");

    useEffect(() => {
        // Check if user credentials are saved in localStorage
        const savedUsername = localStorage.getItem("rememberedUsername");
        const savedPassword = localStorage.getItem("rememberedPassword");
        if (savedUsername && savedPassword) {
            setUsername(savedUsername);
            setPassword(savedPassword);
            setRememberMe(true);
        }
    }, []);

    const handleLogin = async (e) => {
        e.preventDefault();
        setError("");

        try {
            const response = await axios.post("http://127.0.0.1:8075/login", {
                username,
                password
            });

            alert(response.data.message); // Show success message

            if (rememberMe) {
                localStorage.setItem("rememberedUsername", username);
                localStorage.setItem("rememberedPassword", password);
            } else {
                localStorage.removeItem("rememberedUsername");
                localStorage.removeItem("rememberedPassword");
            }

            navigate("/profile"); // Redirect to profile/dashboard after login
        } catch (err) {
            setError(err.response?.data?.detail || "Login failed. Please try again.");
        }
    };

    const handleRegisterClick = (e) => {
        e.preventDefault();
        navigate('/Signup');
    };

    return (
        <div className='wrapper'>
            <div className='form-box login'>
                <form onSubmit={handleLogin}>
                    <h1>Login</h1>
                    <div className='input-box1'>
                        <input 
                            type="text" 
                            placeholder='Username' 
                            value={username} 
                            onChange={(e) => setUsername(e.target.value)} 
                            required 
                        />
                        <FaUser className='icon' />
                    </div>
                    <div className='input-box1'>
                        <input 
                            type="password" 
                            placeholder='Password' 
                            value={password} 
                            onChange={(e) => setPassword(e.target.value)} 
                            required 
                        />
                        <FaLock className='icon' />
                    </div>
                    {error && <p className="error-message">{error}</p>}
                    <div className='remember-forgot'>
                        <label>
                            <input 
                                type='checkbox' 
                                checked={rememberMe} 
                                onChange={(e) => setRememberMe(e.target.checked)}
                            />
                            Remember Me
                        </label>
                        <a href="">Forgot password</a>
                    </div>
                    <button type='submit'>Login</button>
                    <div className='register-link'>
                        <p>Don't have an account? <a href='#' onClick={handleRegisterClick}>Register</a></p>
                    </div>
                </form>
            </div>
        </div>
    );
};

export default LoginRegister;
