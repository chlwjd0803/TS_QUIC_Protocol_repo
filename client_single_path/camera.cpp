#include "camera.h"
#include <opencv2/opencv.hpp>
#include <vector>

extern "C" {

/**
 * @brief 새로운 카메라 객체를 생성하고 그 핸들을 반환합니다.
 *        MJPEG 스트림을 바로 받아서 인코딩 없이 전송 가능.
 */
camera_handle_t camera_create() {
    // /dev/video1이 MJPEG 스트림일 가능성이 높음 → 장치 번호 변경 가능
    cv::VideoCapture* cap = new cv::VideoCapture(0, cv::CAP_V4L2);
    if (!cap || !cap->isOpened()) {
        fprintf(stderr, "카메라 열기 실패 (/dev/video1)\n");
        delete cap;
        return nullptr;
    }

    // MJPEG 모드 설정
    cap->set(cv::CAP_PROP_FOURCC, cv::VideoWriter::fourcc('M','J','P','G'));
    cap->set(cv::CAP_PROP_FRAME_WIDTH, 1280);
    cap->set(cv::CAP_PROP_FRAME_HEIGHT, 720);
    cap->set(cv::CAP_PROP_FPS, 30);

    return static_cast<camera_handle_t>(cap);
}

/**
 * @brief camera_create로 생성된 카메라 객체를 소멸시키고 리소스를 해제합니다.
 */
void camera_destroy(camera_handle_t handle) {
    if (!handle) return;
    cv::VideoCapture* cap = static_cast<cv::VideoCapture*>(handle);
    cap->release();
    delete cap;
}

/**
 * @brief 특정 카메라에서 프레임을 캡처하여 JPEG 데이터로 반환 (MJPEG 직송)
 */
int camera_capture_jpeg(camera_handle_t handle, unsigned char* buffer, int buf_size) {
    if (!handle) {
        fprintf(stderr, "유효하지 않은 카메라 핸들입니다.\n");
        return -1;
    }
    cv::VideoCapture* cap = static_cast<cv::VideoCapture*>(handle);

    cv::Mat frame;
    if (!cap->read(frame)) {
        fprintf(stderr, "프레임 캡처 실패\n");
        return -2;
    }

    // 이미 MJPEG 포맷이므로 imencode 불필요 → OpenCV Mat에서 raw 데이터 추출 불가
    // 대신 MJPEG 캡처 모드에서는 read()로 받은 Mat을 다시 인코딩해야 하는 경우가 있음
    // 여기서는 안전하게 재인코딩 (부하 적음)
    static std::vector<uchar> jpg_buf;
    jpg_buf.clear();
    if (!cv::imencode(".jpg", frame, jpg_buf)) {
        fprintf(stderr, "JPEG 인코딩 실패\n");
        return -3;
    }

    if ((int)jpg_buf.size() > buf_size) {
        fprintf(stderr, "버퍼 크기 부족: 필요 %zu, 제공 %d\n", jpg_buf.size(), buf_size);
        return -4;
    }

    memcpy(buffer, jpg_buf.data(), jpg_buf.size());
    return static_cast<int>(jpg_buf.size());
}

} // extern "C"
