import { useState } from "react";

const AddTutorial = ({ addTutorial }) => {
    const [firstname, setFirstname] = useState("");
    const [lastname, setLastname] = useState("");

    const handleSubmit = (e) => {
        e.preventDefault();
        addTutorial({ firstname, lastname });
        setFirstname("");
        setLastname("");
    };

    return (
        <div className="container text-center mt-4">
            <h1 className="display-4 text-info">Add new employees</h1>
            <form onSubmit={handleSubmit}>
                <div className="mb-3 fs-5">
                    <label htmlFor="title" className="form-label">
                        First name
                    </label>
                    <input
                        type="text"
                        className="form-control fs-5"
                        id="title"
                        placeholder="Enter first name"
                        value={firstname}
                        onChange={(e) => setFirstname(e.target.value)}
                        required
                    />
                </div>
                <div className="mb-3 fs-5">
                    <label htmlFor="desc" className="form-label">
                        Last name
                    </label>
                    <input
                        type="text"
                        className="form-control fs-5"
                        id="desc"
                        placeholder="Enter last name"
                        value={lastname}
                        onChange={(e) => setLastname(e.target.value)}
                        required
                    />
                </div>
                <button className="btn btn-outline-info fs-5  mb-4">
                    Submit
                </button>
            </form>
        </div>
    );
};

export default AddTutorial;
