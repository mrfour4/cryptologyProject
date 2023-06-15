import React, { useEffect, useState } from "react";

const EditItem = ({ editTutorial, item }) => {
    const { _id: id, firstname: newFirstname, lastname } = item;
    const [firstname, setFirstname] = useState(newFirstname);
    const [last, setLast] = useState(lastname);

    useEffect(() => {
        setFirstname(newFirstname);
        setLast(lastname);
    }, [newFirstname, lastname]);

    const handleEdit = (e) => {
        e.preventDefault();
        editTutorial(id, firstname, last);
        setFirstname("");
        setLast("");
    };

    return (
        <div className="modal z-3" tabIndex={-1} id="edit-modal">
            <div className="modal-dialog">
                <div className="modal-content">
                    <div className="modal-header">
                        <h5 className="modal-title">Edit Employee</h5>
                        <button
                            type="button"
                            className="btn-close"
                            data-bs-dismiss="modal"
                            aria-label="Close"
                        />
                    </div>
                    <div className="modal-body">
                        <div className="mb-3 fs-5">
                            <label htmlFor="title" className="form-label">
                                First name
                            </label>
                            <input
                                type="text"
                                className="form-control fs-5"
                                id="title"
                                placeholder="Enter your title"
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
                                placeholder="Enter your Description"
                                value={last}
                                onChange={(e) => setLast(e.target.value)}
                                required
                            />
                        </div>
                    </div>
                    <div className="modal-footer">
                        <button
                            onClick={handleEdit}
                            data-bs-dismiss="modal"
                            type="button"
                            className="btn btn-primary"
                        >
                            Save
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default EditItem;
