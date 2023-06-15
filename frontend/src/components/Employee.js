import { useEffect, useState } from "react";
import Loading from "./Loading";
import TutorialList from "./TutorialList";

import AddTutorial from "./AddTutorial";

import useAxiosPrivate from "../hooks/useAxiosPrivateEmp";

const Employee = () => {
    const [tutorial, setTutorial] = useState();
    const [loading, setLoading] = useState(true);

    const axiosPrivate = useAxiosPrivate();

    const getData = async () => {
        try {
            const { data } = await axiosPrivate.get("/employees");
            setTutorial(data);
            setLoading(false);
        } catch (error) {
            console.log(error);
        }
    };

    useEffect(() => {
        getData();
    }, []);

    const addTutorial = async (tutorial) => {
        try {
            await axiosPrivate.post("/employees", tutorial);
        } catch (error) {
            console.log(error);
        }
        getData();
    };

    const deleteTutorial = async (id) => {
        try {
            const message = { id: id };
            console.log("message: ", message);
            await axiosPrivate.delete("/employees", { data: message });
        } catch (error) {
            console.log(error);
        }
        getData();
    };

    const editTutorial = async (id, firstname, lastname) => {
        const filtered = tutorial
            .filter((tutor) => tutor.id === id)
            .map((tutor) => ({ firstname, lastname }));

        try {
            await axiosPrivate.put("/employees", filtered);
        } catch (error) {
            console.log(error);
        }
        getData();
    };

    return (
        <>
            {loading ? (
                <Loading />
            ) : (
                <>
                    <AddTutorial addTutorial={addTutorial} />
                    {console.log("Tutorial: ", tutorial)}
                    <TutorialList
                        tutorials={tutorial}
                        deleteTutorial={deleteTutorial}
                        editTutorial={editTutorial}
                    />
                </>
            )}
        </>
    );
};

export default Employee;
