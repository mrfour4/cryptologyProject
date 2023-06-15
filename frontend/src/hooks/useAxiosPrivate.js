import { useEffect } from "react";
import { axiosPrivate } from "../api/axios";
import useAuth from "./useAuth";
import useRefreshToken from "./useRefreshToken";

import { decryptData, encryptData } from "../utils/secureData";

const useAxiosPrivate = () => {
    const refresh = useRefreshToken();
    const { auth } = useAuth();

    useEffect(() => {
        const requestIntercept = axiosPrivate.interceptors.request.use(
            (config) => {
                if (!config.headers["Authorization"]) {
                    config.headers[
                        "Authorization"
                    ] = `Bearer ${auth?.accessToken}`;
                }

                // console.log("req.data: ", config.data);

                if (config.data) {
                    const message = config.data;
                    config.data = encryptData(
                        auth.privateKeyRaw,
                        auth.privateKeyPem,
                        message,
                        auth.severPubKeyRaw
                    );
                    console.log("cipher: ", config.data);
                }
                return config;
            },
            (error) => Promise.reject(error)
        );

        const responseIntercept = axiosPrivate.interceptors.response.use(
            (response) => {
                if (response.data) {
                    const cipher = response.data;
                    response.data = decryptData(
                        auth.severPubKeyRaw,
                        auth.severPubKeyPem,
                        cipher,
                        auth.privateKeyRaw
                    );
                    console.log("response.data: ", response);
                }
                return response;
            },
            async (error) => {
                const prevRequest = error?.config;
                if (error?.response?.status === 403 && !prevRequest?.sent) {
                    prevRequest.sent = true;
                    const newAccessToken = await refresh();
                    prevRequest.headers[
                        "Authorization"
                    ] = `Bearer ${newAccessToken}`;
                    return axiosPrivate(prevRequest);
                }
                return Promise.reject(error);
            }
        );

        return () => {
            axiosPrivate.interceptors.request.eject(requestIntercept);
            axiosPrivate.interceptors.response.eject(responseIntercept);
        };
    }, [auth, refresh]);

    return axiosPrivate;
};

export default useAxiosPrivate;
