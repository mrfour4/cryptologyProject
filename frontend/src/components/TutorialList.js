import { useState } from "react";
import { AiFillDelete } from "react-icons/ai";

const TutorialList = ({ tutorials, deleteTutorial, editTutorial }) => {
    const [item, setItem] = useState("");

    return (
        <div className="container mt-4">
            <table className="table table-dark fs-5 table-striped">
                <thead>
                    <tr>
                        <th scope="col">First name</th>
                        <th scope="col">Last name</th>
                        <th scope="col" className="text-center text-nowrap">
                            Edit
                        </th>
                    </tr>
                </thead>
                <tbody>
                    {tutorials?.map((item) => {
                        const { _id: id, firstname, lastname } = item;
                        console.log("item: ", item);
                        return (
                            <tr key={id}>
                                <td>{firstname}</td>
                                <td>{lastname}</td>
                                <td className="text-center">
                                    {/* <FaEdit
                                        size={20}
                                        className="me-3 text-info cursor "
                                        data-bs-toggle="modal"
                                        data-bs-target="#edit-modal"
                                        onClick={() => {
                                            setItem(item);
                                        }}
                                    /> */}
                                    <AiFillDelete
                                        size={22}
                                        className="text-danger cursor"
                                        onClick={() => {
                                            deleteTutorial(item._id);
                                        }}
                                    />
                                </td>
                            </tr>
                        );
                    })}
                </tbody>
            </table>
            {/* <EditItem editTutorial={editTutorial} item={item} /> */}
        </div>
    );
};

export default TutorialList;
