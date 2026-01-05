#ifndef CAMERA_H
#define CAMERA_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 카메라 객체를 가리키는 포인터 (핸들).
 */
typedef void* camera_handle_t;   // ← 이것 그대로 사용

/**
 * @brief 새로운 카메라 객체를 생성하고 그 핸들을 반환합니다.
 * @return 성공 시 카메라 핸들, 실패 시 NULL을 반환합니다.
 */
camera_handle_t camera_create();

/**
 * @brief camera_create로 생성된 카메라 객체를 소멸시키고 리소스를 해제합니다.
 * @param handle 소멸시킬 카메라의 핸들
 */
void camera_destroy(camera_handle_t handle);

/**
 * @brief 특정 카메라에서 프레임을 캡처하여 JPEG 형식으로 인코딩합니다.
 * @param handle 작업을 수행할 카메라의 핸들
 * @param buffer JPEG 데이터를 저장할 버퍼
 * @param buf_size 버퍼의 크기
 * @return 성공 시 저장된 JPEG 데이터의 크기(바이트), 실패 시 음수 값을 반환합니다.
 */
int camera_capture_jpeg(camera_handle_t handle, unsigned char* buffer, int buf_size);

#ifdef __cplusplus
}
#endif

#endif // CAMERA_H