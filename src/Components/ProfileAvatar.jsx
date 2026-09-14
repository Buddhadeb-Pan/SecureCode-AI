import { useState } from "react";
import "./ProfileAvatar.css";

export function getProfileInitials(name = "") {
  const nameParts = String(name)
    .trim()
    .split(/\s+/)
    .filter(Boolean);

  if (nameParts.length === 0) {
    return "U";
  }

  if (nameParts.length === 1) {
    return (Array.from(nameParts[0])[0] || "U").toUpperCase();
  }

  const firstInitial = Array.from(nameParts[0])[0] || "";
  const lastInitial = Array.from(nameParts[nameParts.length - 1])[0] || "";

  return `${firstInitial}${lastInitial}`.toUpperCase();
}

function ProfileAvatar({
  name = "",
  imageUrl = "",
  size = "medium",
  className = "",
}) {
  const normalizedImageUrl =
    typeof imageUrl === "string" ? imageUrl.trim() : "";
  const [failedImageUrl, setFailedImageUrl] = useState("");
  const showImage =
    normalizedImageUrl && normalizedImageUrl !== failedImageUrl;

  const avatarClassName = [
    "profile-avatar",
    `profile-avatar--${size}`,
    className,
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <span
      className={avatarClassName}
      aria-label={`${name || "User"} profile avatar`}
      role="img"
    >
      {showImage ? (
        <img
          src={normalizedImageUrl}
          alt=""
          className="profile-avatar-image"
          onError={() => setFailedImageUrl(normalizedImageUrl)}
        />
      ) : (
        <span aria-hidden="true">{getProfileInitials(name)}</span>
      )}
    </span>
  );
}

export default ProfileAvatar;
